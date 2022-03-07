pub fn read_u16_be(bs: &[u8]) -> u16 {
    assert!(bs.len() >= 2);
    u16::from_be_bytes(bs[..2].try_into().unwrap())
}

pub fn read_u16_le(bs: &[u8]) -> u16 {
    assert!(bs.len() >= 2);
    u16::from_le_bytes(*<&[u8; 2]>::try_from(&bs[..2]).unwrap())
}

pub fn read_u32_be(bs: &[u8]) -> u32 {
    assert!(bs.len() >= 4);
    u32::from_be_bytes(*<&[u8; 4]>::try_from(&bs[..4]).unwrap())
}

pub fn read_u32_le(bs: &[u8]) -> u32 {
    assert!(bs.len() >= 4);
    u32::from_le_bytes(*<&[u8; 4]>::try_from(&bs[..4]).unwrap())
}

pub fn read_u64_be(bs: &[u8]) -> u64 {
    assert!(bs.len() >= 8);
    u64::from_be_bytes(*<&[u8; 8]>::try_from(&bs[..8]).unwrap())
}

pub fn read_u64_le(bs: &[u8]) -> u64 {
    assert!(bs.len() >= 8);
    u64::from_le_bytes(*<&[u8; 8]>::try_from(&bs[..8]).unwrap())
}

pub fn write_u16_be(bs: &mut [u8], v: u16) {
    assert!(bs.len() >= 2);
    bs[0..2].copy_from_slice(v.to_be_bytes().as_slice())
}
