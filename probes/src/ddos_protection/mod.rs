#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct SAddrV4 {
    pub addr: u32,
    pub port: u32, // u32 instead of u16 to align properly
}
