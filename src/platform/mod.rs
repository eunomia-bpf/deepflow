mod kubernetes;
mod libvirt_xml_extractor;
mod platform_synchronizer;

pub use libvirt_xml_extractor::LibvirtXmlExtractor;

use crate::utils::net::MacAddr;

#[derive(Debug)]
pub enum PollerType {
    Adaptive,
    Active,
    Passive,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub mac: MacAddr,
    pub domain_uuid: String,
    pub domain_name: String,
}
