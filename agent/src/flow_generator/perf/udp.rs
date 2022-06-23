use std::cmp::max;
use std::time::Duration;

use crate::common::{
    enums::PacketDirection,
    flow::{FlowPerfStats, L4Protocol},
    meta_packet::MetaPacket,
};
use crate::flow_generator::error::{Error, Result};

use super::{L4FlowPerf, ART_MAX};

#[derive(Debug, Default)]
pub struct UdpPerf {
    req_timestamp: Duration,
    art_max: Duration,
    art_sum: Duration,
    art_count: u32,
    last_pkt_direction: PacketDirection,
    data_update_flag: bool,
}

impl UdpPerf {
    pub fn new() -> Self {
        UdpPerf::default()
    }
}

impl L4FlowPerf for UdpPerf {
    fn parse(&mut self, header: &MetaPacket, _: bool) -> Result<()> {
        if header.payload_len == 0 {
            return Err(Error::ZeroPayloadLen);
        }

        let pkt_timestamp = header.lookup_key.timestamp;
        if header.direction == PacketDirection::ClientToServer {
            self.req_timestamp = pkt_timestamp;
        } else if self.req_timestamp != Duration::ZERO
            && header.direction != self.last_pkt_direction
        {
            let art = pkt_timestamp - self.req_timestamp;
            if art <= ART_MAX {
                self.art_max = max(self.art_max, art);
                self.art_sum += art;
                self.art_count += 1;
                self.data_update_flag = true;
            }
        }

        self.last_pkt_direction = header.direction;

        Ok(())
    }

    fn data_updated(&self) -> bool {
        self.data_update_flag
    }

    fn copy_and_reset_data(&mut self, _: bool) -> FlowPerfStats {
        let mut stats = FlowPerfStats::default();
        stats.l4_protocol = L4Protocol::Udp;
        stats.tcp.art_max = (self.art_max.as_nanos() / Duration::from_micros(1).as_nanos()) as u32;
        stats.tcp.art_sum = (self.art_sum.as_nanos() / Duration::from_micros(1).as_nanos()) as u32;
        stats.tcp.art_count = self.art_count;

        stats
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::utils::test::Capture;

    use super::*;

    const FILE_DIR: &'static str = "resources/test/flow_generator";

    fn update_from_pcap<P: AsRef<Path>>(path: P, reverse_pkt: bool) -> (UdpPerf, String) {
        let capture = Capture::load_pcap(path, None);
        let packets = capture.as_meta_packets();
        let mut flow_perf = UdpPerf::new();
        let mut result = String::from("");

        let first_pkt_src_ip = packets[0].lookup_key.src_ip;
        for (i, mut pkt) in packets.into_iter().enumerate() {
            if first_pkt_src_ip == pkt.lookup_key.src_ip {
                pkt.direction = PacketDirection::ClientToServer;
            } else {
                pkt.direction = PacketDirection::ServerToClient;
            }

            if reverse_pkt {
                pkt.direction = pkt.direction.reversed();
            }

            flow_perf.parse(&pkt, false).unwrap();
            result.push_str(format!("{}th udp perf data:\n{:?}\n\n", i, flow_perf).as_str());
        }

        (flow_perf, result)
    }

    fn udp_perf_helper<P: AsRef<Path>>(path: P, result_path: P, reverse_pkt: bool) {
        let (_, actual) = update_from_pcap(path, reverse_pkt);
        let result = fs::read_to_string(result_path).unwrap();
        assert_eq!(result, actual)
    }

    fn udp_report_helper<P: AsRef<Path>>(path: P, result_path: P, reverse_pkt: bool) {
        let (mut flow_perf, _) = update_from_pcap(path, reverse_pkt);
        let stats = flow_perf.copy_and_reset_data(false);
        let actual = format!("{:?}\n", stats);
        let result = fs::read_to_string(result_path).unwrap();
        assert_eq!(result, actual)
    }

    #[test]
    fn udp_normal() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_normal.pcap"),
            Path::new(FILE_DIR).join("udp_normal.result"),
            false,
        )
    }

    #[test]
    fn upd_single_packet() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_1_packet.pcap"),
            Path::new(FILE_DIR).join("udp_1_packet.result"),
            true,
        )
    }

    #[test]
    fn udp_continuous_packet() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_continuous_packet.pcap"),
            Path::new(FILE_DIR).join("udp_continuous_packet.result"),
            false,
        )
    }

    #[test]
    fn udp_report() {
        udp_perf_helper(
            Path::new(FILE_DIR).join("udp_normal.pcap"),
            Path::new(FILE_DIR).join("udp_report_packet.result"),
            false,
        )
    }
}