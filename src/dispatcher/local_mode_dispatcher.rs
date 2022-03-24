use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::str;
use std::sync::{atomic::Ordering, Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, info, log_enabled, warn};
use regex::Regex;

use super::base_dispatcher::{BaseDispatcher, BaseDispatcherListener};

use crate::{
    common::{
        decapsulate::TunnelType,
        enums::{EthernetType, TapType},
        MetaPacket, PlatformData, TapPort, FIELD_OFFSET_ETH_TYPE, MAC_ADDR_LEN, VLAN_HEADER_SIZE,
    },
    config::RuntimeConfig,
    flow_generator::FlowMap,
    platform::LibvirtXmlExtractor,
    proto::{common::TridentType, trident::IfMacSource},
    utils::{
        bytes::read_u16_be,
        net::{link_list, Link, MacAddr, MAC_ADDR_ZERO},
    },
};

pub(super) struct LocalModeDispatcher {
    pub(super) base: BaseDispatcher,
    pub(super) extractor: Arc<LibvirtXmlExtractor>,
}

impl LocalModeDispatcher {
    pub(super) fn run(&mut self) {
        let base = &mut self.base;
        info!("Start dispatcher {}", base.id);
        let mut prev_timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        // TODO: fix flow-map parameters
        let mut flow_map = FlowMap::new(
            42,
            base.id as u32,
            base.flow_output_queue.clone(),
            |_, _| {},
            false,
            base.log_output_queue.clone(),
            vec![],
            65536,
            Default::default(),
            Default::default(),
            Default::default(),
        );
        while !base.terminated.load(Ordering::Relaxed) {
            if base.reset_whitelist.swap(false, Ordering::Relaxed) {
                base.tap_interface_whitelist.reset();
            }
            let recved = BaseDispatcher::recv(
                &mut base.engine,
                &base.leaky_bucket,
                &mut prev_timestamp,
                &base.counter,
            );
            if recved.is_none() {
                flow_map.inject_flush_ticker(Duration::ZERO);
                if base.tap_interface_whitelist.next_sync(Duration::ZERO) {
                    base.need_update_ebpf.store(true, Ordering::Relaxed);
                }
                continue;
            }
            let (packet, mut timestamp) = recved.unwrap();

            let pipeline = {
                let pipelines = base.pipelines.lock().unwrap();
                if let Some(p) = pipelines.get(&(packet.if_index as u32)) {
                    p.clone()
                } else if pipelines.is_empty() {
                    continue;
                } else {
                    // send to one of the pipelines if packet is LLDP
                    let mut eth_type = read_u16_be(&packet.data[FIELD_OFFSET_ETH_TYPE..]);
                    if eth_type == EthernetType::Dot1Q {
                        eth_type =
                            read_u16_be(&packet.data[FIELD_OFFSET_ETH_TYPE + VLAN_HEADER_SIZE..]);
                    }
                    if eth_type != EthernetType::LinkLayerDiscovery {
                        continue;
                    }
                    pipelines.iter().next().unwrap().1.clone()
                }
            };
            let mut pipeline = pipeline.lock().unwrap();

            if timestamp + Duration::from_millis(1) < pipeline.timestamp {
                // FIXME: just in case
                base.counter
                    .kernel_counter
                    .retired
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            } else if timestamp < pipeline.timestamp {
                timestamp = pipeline.timestamp;
            }

            pipeline.timestamp = timestamp;

            // compare 4 low bytes
            let (src_local, dst_local) = if pipeline.vm_mac.octets()[2..]
                == packet.data[MAC_ADDR_LEN + 2..MAC_ADDR_LEN + MAC_ADDR_LEN]
            {
                // src mac
                (true, false)
            } else if pipeline.vm_mac.octets()[2..] == packet.data[2..MAC_ADDR_LEN]
                && MacAddr::is_multicast(packet.data)
            {
                // dst mac
                (false, true)
            } else {
                (false, false)
            };

            // LOCAL模式L2END使用underlay网络的MAC地址，实际流量解析使用overlay

            let tunnel_type_bitmap = base.tunnel_type_bitmap.lock().unwrap().clone();
            let decap_length = match BaseDispatcher::decap_tunnel(
                packet.data,
                &base.tap_type_handler,
                &mut base.tunnel_info,
                tunnel_type_bitmap,
            ) {
                Ok((l, _)) => l,
                Err(e) => {
                    base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                    warn!("decap_tunnel failed: {:?}", e);
                    continue;
                }
            };
            let overlay_packet = &packet.data[decap_length..];
            let mut meta_packet = MetaPacket::empty();
            // TODO: use ntp time
            let offset = Duration::ZERO;
            if let Err(e) = meta_packet.update(
                overlay_packet,
                src_local,
                dst_local,
                timestamp + offset,
                packet.data.len() - decap_length,
            ) {
                base.counter.invalid_packets.fetch_add(1, Ordering::Relaxed);
                warn!("meta_packet update failed: {:?}", e);
                continue;
            }

            if base.tunnel_info.tunnel_type != TunnelType::None {
                meta_packet.tunnel = Some(&base.tunnel_info);
                if base.tunnel_info.tunnel_type == TunnelType::TencentGre
                    || base.tunnel_info.tunnel_type == TunnelType::Vxlan
                {
                    // 腾讯TCE、青云私有云需要通过TunnelID查询云平台信息
                    // 这里只需要考虑单层隧道封装的情况
                    // 双层封装的场景下认为内层MAC存在且有效（VXLAN-VXLAN）或者需要通过IP来判断（VXLAN-IPIP）
                    meta_packet.lookup_key.tunnel_id = base.tunnel_info.id;
                }
            } else {
                // 无隧道并且MAC地址都是0一定是loopback流量
                if meta_packet.lookup_key.src_mac == MAC_ADDR_ZERO
                    && meta_packet.lookup_key.dst_mac == MAC_ADDR_ZERO
                {
                    meta_packet.lookup_key.src_mac = base.ctrl_mac;
                    meta_packet.lookup_key.dst_mac = base.ctrl_mac;
                    meta_packet.lookup_key.l2_end_0 = true;
                    meta_packet.lookup_key.l2_end_1 = true;
                }
            }

            meta_packet.tap_port = TapPort::from_local_mac(
                base.tunnel_info.tunnel_type,
                u64::from(pipeline.vm_mac) as u32,
            );
            BaseDispatcher::prepare_flow(&mut meta_packet, TapType::Tor, false, base.id as u8);
            for h in pipeline.handlers.iter_mut() {
                h.handle(
                    overlay_packet,
                    &meta_packet,
                    meta_packet.endpoint_data.as_ref().clone(),
                    meta_packet.policy_data.as_ref().clone(),
                );
            }

            if let Some(policy) = meta_packet.policy_data.as_ref() {
                if policy.acl_id > 0 {
                    // 如果匹配策略则认为需要拷贝整个包
                    base.tap_interface_whitelist.add(packet.if_index as usize);
                }
            }
            if base
                .tap_interface_whitelist
                .next_sync(meta_packet.lookup_key.timestamp)
            {
                base.need_update_ebpf.store(true, Ordering::Relaxed);
            }
            flow_map.inject_meta_packet(meta_packet);
        }
        info!("Stopped dispatcher {}", base.id);
    }

    pub(super) fn listener(&self) -> LocalModeDispatcherListener {
        LocalModeDispatcherListener::new(self.base.listener(), self.extractor.clone())
    }
}

#[derive(Clone)]
pub struct LocalModeDispatcherListener {
    base: BaseDispatcherListener,
    extractor: Arc<LibvirtXmlExtractor>,
    rewriter: MacRewriter,
}

impl LocalModeDispatcherListener {
    pub(super) fn new(base: BaseDispatcherListener, extractor: Arc<LibvirtXmlExtractor>) -> Self {
        Self {
            base,
            extractor,
            rewriter: MacRewriter::new(),
        }
    }

    pub(super) fn on_config_change(&mut self, config: &RuntimeConfig) {
        self.base.on_config_change(config)
    }

    pub fn on_vm_change(&self, _: &[MacAddr]) {}

    pub fn on_tap_interface_change(
        &self,
        interfaces: &Vec<Link>,
        if_mac_source: IfMacSource,
        trident_type: TridentType,
        blacklist: &Vec<PlatformData>,
    ) {
        let mut interfaces = interfaces.to_vec();
        if !blacklist.is_empty() {
            // 当虚拟机内的容器节点已部署采集器时，宿主机采集器需要排除容器节点的接口，避免采集双份重复流量
            let mut blackset = HashSet::with_capacity(blacklist.len());
            for entry in blacklist {
                blackset.insert(entry.mac);
            }
            let mut rejected = vec![];
            interfaces.retain(|iface| {
                if blackset.contains(&iface.mac_addr.into()) {
                    rejected.push(iface.mac_addr);
                    false
                } else {
                    true
                }
            });
            if !rejected.is_empty() {
                debug!("Tap interfaces {:?} rejected by blacklist", rejected);
            }
        }
        // interfaces为实际TAP口的集合，macs为TAP口对应主机的MAC地址集合
        let keys = interfaces
            .iter()
            .map(|link| link.if_index)
            .collect::<Vec<_>>();
        let macs = self.get_mapped_macs(
            &interfaces,
            if_mac_source,
            trident_type,
            &self.base.options.tap_mac_script,
        );
        self.base.on_vm_change(&keys, &macs);
        self.base.on_tap_interface_change(interfaces, if_mac_source);
    }

    fn get_mapped_macs(
        &self,
        interfaces: &Vec<Link>,
        if_mac_source: IfMacSource,
        trident_type: TridentType,
        tap_mac_script: &str,
    ) -> Vec<MacAddr> {
        let mut macs = vec![];
        let index_to_mac_map = Self::get_if_index_to_inner_mac_map();
        let name_to_mac_map = self.get_if_name_to_mac_map(tap_mac_script);

        for iface in interfaces.iter() {
            if !index_to_mac_map.is_empty() {
                // kubernetes环境POD场景，需要根据平台数据来获取TAP口对应的主机MAC
                if let Some(mac) = index_to_mac_map.get(&iface.if_index) {
                    macs.push(*mac);
                    continue;
                }
            }
            macs.push(match if_mac_source {
                IfMacSource::IfMac => {
                    let mut mac = iface.mac_addr;
                    if trident_type == TridentType::TtProcess {
                        let mut octets = mac.octets();
                        octets[0] = 0;
                        mac = octets.into();
                    }
                    mac
                }
                IfMacSource::IfName => {
                    let new_mac = self.rewriter.regenerate_mac(iface);
                    if log_enabled!(log::Level::Debug) && new_mac != iface.mac_addr {
                        debug!(
                            "interface {} rewrite mac {} -> {}",
                            iface.name, iface.mac_addr, new_mac
                        );
                    }
                    new_mac
                }
                IfMacSource::IfLibvirtXml => {
                    *name_to_mac_map.get(&iface.name).unwrap_or(&iface.mac_addr)
                }
            });
        }
        macs
    }

    fn get_if_index_to_inner_mac_map() -> HashMap<u32, MacAddr> {
        let mut result = HashMap::new();

        // TODO: sniffer entries from platform.GetMacEntries()

        match link_list() {
            Ok(links) => {
                for link in links {
                    if link.mac_addr != MAC_ADDR_ZERO && !result.contains_key(&link.if_index) {
                        result.insert(link.if_index, link.mac_addr);
                    }
                }
            }
            Err(e) => warn!("failed getting link list: {:?}", e),
        }

        result
    }

    fn get_if_name_to_mac_map(&self, tap_mac_script: &str) -> HashMap<String, MacAddr> {
        let mut result = HashMap::new();
        if let Some(entries) = self.extractor.get_entries() {
            debug!("Xml Mac:");
            for entry in entries {
                debug!("\tif_name: {}, mac: {}", entry.name, entry.mac);
                result.insert(entry.name, entry.mac);
            }
        }
        if tap_mac_script != "" {
            match Command::new(&tap_mac_script).output() {
                Ok(output) => Self::parse_tap_mac_script_output(&mut result, &output.stdout),
                Err(e) => warn!("Exec {} failed: {:?}", tap_mac_script, e),
            }
        }
        result
    }

    fn parse_tap_mac_script_output(result: &mut HashMap<String, MacAddr>, bytes: &[u8]) {
        let mut iter = bytes.split(|x| *x == b'\n');
        while let Some(line) = iter.next() {
            let mut kvs = line.split(|x| *x == b',');
            let name = kvs.next();
            let mac = kvs.next();
            if name.is_none() || mac.is_none() || kvs.next().is_some() {
                warn!(
                    "Static-config tap-mac-map has invalid item: {}",
                    str::from_utf8(line).unwrap()
                );
            }
            let name = str::from_utf8(name.unwrap()).unwrap();
            if result.contains_key(name) {
                debug!(
                    "Ignore static-config tap-mac-map: {}",
                    str::from_utf8(line).unwrap()
                );
            } else if let Ok(mac) = str::from_utf8(mac.unwrap()).unwrap().parse() {
                result.insert(name.to_owned(), mac);
            }
        }
    }
}

#[derive(Clone)]
struct MacRewriter {
    contrail_regex: Regex,
    qing_cloud_vm_regex: Regex,
    qing_cloud_sriov_regex: Regex,
    qing_cloud_sriov_mac_regex: Regex,
}

impl MacRewriter {
    const CONTRAIL_REGEX: &'static str = "^tap[0-9a-f]{8}-[0-9a-f]{2}$";
    const QING_CLOUD_VM_REGEX: &'static str = "^[0-9a-f]{8}";
    const QING_CLOUD_SRIOV_REGEX: &'static str = "^[0-9a-zA-Z]+_[0-9]{1,3}$";
    const QING_CLOUD_SRIOV_MAC_REGEX: &'static str = "^52:54:9b";

    pub fn new() -> Self {
        Self {
            // Contrail中，tap口的MAC与虚拟机内部MAC无关，但其名字后缀是虚拟机MAC后缀
            contrail_regex: Regex::new(Self::CONTRAIL_REGEX).unwrap(),
            qing_cloud_vm_regex: Regex::new(Self::QING_CLOUD_VM_REGEX).unwrap(),
            qing_cloud_sriov_regex: Regex::new(Self::QING_CLOUD_SRIOV_REGEX).unwrap(),
            qing_cloud_sriov_mac_regex: Regex::new(Self::QING_CLOUD_SRIOV_MAC_REGEX).unwrap(),
        }
    }

    pub fn regenerate_mac(&self, interface: &Link) -> MacAddr {
        let ifname = &interface.name;
        if self.contrail_regex.is_match(ifname) {
            // safe unwrap because string matched
            let mac_4b = u64::from_str_radix(&ifname[3..11], 16).unwrap();
            let mac_1b = u64::from_str_radix(&ifname[12..14], 16).unwrap();
            MacAddr::try_from(mac_4b << 8 | mac_1b).unwrap()
        } else if self.qing_cloud_vm_regex.is_match(ifname) {
            // safe unwrap because string matched
            MacAddr::try_from(u64::from_str_radix(&ifname[..8], 16).unwrap()).unwrap()
        } else if self.qing_cloud_sriov_regex.is_match(ifname) {
            self.get_mac_by_bridge_fdb(interface)
                .unwrap_or(interface.mac_addr)
        } else {
            interface.mac_addr
        }
    }

    fn get_mac_by_bridge_fdb(&self, interface: &Link) -> Option<MacAddr> {
        let output = match Command::new("bridge")
            .args(["fdb", "show", "dev", &interface.name])
            .output()
        {
            Ok(output) => output.stdout,
            Err(e) => {
                warn!("bridge command failed: {}", e);
                return None;
            }
        };
        for line in output.split(|x| *x == b'\n') {
            let mut iter = line.split(|x| *x == b' ');
            if let Some(part) = iter.next() {
                let s = str::from_utf8(part).unwrap();
                if self.qing_cloud_sriov_mac_regex.is_match(s) {
                    return match s.parse::<MacAddr>() {
                        Ok(mac) => Some(mac),
                        Err(e) => {
                            warn!("{:?}", e);
                            None
                        }
                    };
                }
            }
        }
        warn!("interface mac not found in bridge fdb");
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_rewrite() {
        let rewriter = MacRewriter::new();
        for case in vec![
            (
                "qingcloud2",
                Link {
                    name: "aabbccdd".into(),
                    mac_addr: "a1:01:02:03:04:05".parse().unwrap(),
                    ..Default::default()
                },
                "00:00:aa:bb:cc:dd",
            ),
            (
                "qingcloud",
                Link {
                    name: "aabbccdd@if252".into(),
                    mac_addr: "a1:01:02:03:04:05".parse().unwrap(),
                    ..Default::default()
                },
                "00:00:aa:bb:cc:dd",
            ),
            (
                "tap",
                Link {
                    name: "tap01234567-89".into(),
                    mac_addr: "a1:01:02:03:04:05".parse().unwrap(),
                    ..Default::default()
                },
                "00:01:23:45:67:89",
            ),
            (
                "lo",
                Link {
                    name: "lo".into(),
                    mac_addr: "00:00:00:00:00:01".parse().unwrap(),
                    ..Default::default()
                },
                "00:00:00:00:00:01",
            ),
        ] {
            assert_eq!(
                &rewriter.regenerate_mac(&case.1).to_string(),
                case.2,
                "case {} failed",
                case.0
            );
        }
    }

    #[test]
    fn parse_mac_script_output() {
        let bs = "abcdefg,11:22:33:44:55:66";
        let mut m = HashMap::new();
        LocalModeDispatcherListener::parse_tap_mac_script_output(&mut m, bs.as_bytes());
        assert_eq!(
            m.get("abcdefg".into()),
            Some(&"11:22:33:44:55:66".parse().unwrap())
        );
    }
}
