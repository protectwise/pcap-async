use crate::{pcap_util, Error};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use byteorder::{BigEndian, WriteBytesExt};
use std::mem;

#[derive(Clone, Debug)]
pub struct Info {
    pub name: String,
    pub ips: Vec<IpAddr>,
}

impl Info {
    pub fn all() -> Result<Vec<Info>, Error> {
        let mut err_buf = vec![0u8 as std::os::raw::c_char; pcap_sys::PCAP_ERRBUF_SIZE as _];
        let mut device_result: *mut pcap_sys::pcap_if_t = std::ptr::null_mut();

        unsafe {
            let buf = std::mem::transmute::<
                &mut *mut pcap_sys::pcap_if_t,
                *mut *mut pcap_sys::pcap_if_t,
            >(&mut device_result);
            if 0 != pcap_sys::pcap_findalldevs(buf, err_buf.as_mut_ptr()) {
                let err: Vec<_> = err_buf.iter().map(|v| *v as u8).collect();
                let err_str =
                    std::ffi::CStr::from_bytes_with_nul(err.as_ref()).map_err(Error::FfiNul)?;
                let utf_str = err_str.to_str().map_err(Error::Utf8)?;
                return Err(Error::LibPcapError {
                    msg: utf_str.to_owned(),
                });
            }
        }

        let mut result = vec![];

        while device_result != std::ptr::null_mut() {
            let device_name_ptr = unsafe { (*device_result).name };
            let device_name = pcap_util::cstr_to_string(device_name_ptr)?;
            let mut device_addrs = unsafe { (*device_result).addresses };
            let mut addresses = vec![];
            while device_addrs != std::ptr::null_mut() {
                let addr = unsafe { (*device_addrs).addr };
                if addr != std::ptr::null_mut() {
                    let sockaddr = addr as *mut libc::sockaddr;
                    match unsafe { (*sockaddr).sa_family } as i32 {
                        libc::AF_INET => {
                            let ip_addr =
                                unsafe {
                                    let sock = sockaddr as *mut libc::sockaddr_in;
                                    let sockaddr = (*sock).sin_addr.s_addr;
                                    let sockaddr = mem::transmute::<u32, [u8; 4]>(sockaddr);
                                    let sockaddr = Ipv4Addr::from(sockaddr);
                                    sockaddr

                                };
                            addresses.push(IpAddr::V4(ip_addr));
                        }
                        libc::AF_INET6 => {
                            let ip_addr = unsafe {
                                //*(sockaddr as *mut libc::sockaddr_in6 as *mut Ipv6Addr)
                                let sock = sockaddr as *mut libc::sockaddr_in6;
                                let sockaddr = (*sock).sin6_addr.s6_addr;
                                let sockaddr = Ipv6Addr::from(sockaddr);
                                sockaddr
                            };
                            addresses.push(IpAddr::V6(ip_addr));
                        }
                        _ => {
                            //not a type we care about
                        }
                    }
                }
                device_addrs = unsafe { (*device_addrs).next };
            }
            result.push(Info {
                name: device_name,
                ips: addresses,
            });
            device_result = unsafe { (*device_result).next };
        }

        return Ok(result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info_all() {
        let infos = Info::all().expect("Failed to list");

        println!("Devices={:?}", infos);

        assert!(infos.is_empty() == false);
    }
}
