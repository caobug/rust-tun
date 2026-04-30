//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use std::io;
use std::net::IpAddr;
use std::process::Command;

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegOpenKeyExW, RegSetValueExW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_PARAMCHANGE, SERVICE_PAUSE_CONTINUE, SERVICE_STATUS,
};
use windows_sys::core::GUID;

struct LibraryHandle(HMODULE);

impl LibraryHandle {
    fn load(name: &str) -> Option<Self> {
        let handle = unsafe { LoadLibraryW(to_wide_null(name).as_ptr()) };
        if handle.is_null() {
            None
        } else {
            Some(Self(handle))
        }
    }
}

impl Drop for LibraryHandle {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

pub(crate) fn set_dns_servers(
    adapter_guid: u128,
    adapter_name: &str,
    dns_servers: &[IpAddr],
) -> io::Result<()> {
    if dns_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "dns_servers must not be empty; clearing DNS is not supported",
        ));
    }

    if !is_valid_adapter_name(adapter_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "adapter_name contains characters that cannot be safely passed to netsh",
        ));
    }

    let guid = GUID::from_u128(adapter_guid);

    let api_err = match set_via_api(&guid, dns_servers) {
        Ok(()) => {
            log::debug!("DNS set via SetInterfaceDnsSettings");
            return Ok(());
        }
        Err(e) => e,
    };
    log::debug!("SetInterfaceDnsSettings unavailable or failed: {api_err}");

    let reg_err = match set_via_registry(&guid, dns_servers) {
        Ok(()) => {
            log::debug!("DNS set via registry");
            return Ok(());
        }
        Err(e) => e,
    };
    log::debug!("registry DNS write failed: {reg_err}");

    match set_via_netsh(adapter_name, dns_servers) {
        Ok(()) => {
            log::debug!("DNS set via netsh");
            Ok(())
        }
        Err(e) => {
            log::error!(
                "all DNS configuration paths failed (api: {api_err}, registry: {reg_err}, netsh: {e})"
            );
            Err(e)
        }
    }
}

#[repr(C)]
#[allow(non_snake_case)]
#[derive(Default)]
struct DnsInterfaceSettings {
    Version: u32,
    Flags: u64,
    Domain: *const u16,
    NameServer: *const u16,
    SearchList: *const u16,
    RegistrationEnabled: u32,
    RegisterAdapterName: u32,
    EnableLLMNR: u32,
    QueryAdapterName: u32,
    ProfileNameServer: *const u16,
}

fn set_via_api(guid: &GUID, dns_servers: &[IpAddr]) -> io::Result<()> {
    let lib = LibraryHandle::load("iphlpapi.dll")
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;

    type SetDnsFn = unsafe extern "system" fn(GUID, *const DnsInterfaceSettings) -> u32;
    let func: SetDnsFn = unsafe {
        let proc = GetProcAddress(lib.0, c"SetInterfaceDnsSettings".as_ptr().cast())
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        std::mem::transmute::<_, SetDnsFn>(proc)
    };

    let name_server = to_wide_null(&dns_to_comma_separated(dns_servers));
    let settings = DnsInterfaceSettings {
        Version: 1,
        Flags: 0x0002, // DNS_SETTING_NAMESERVER
        NameServer: name_server.as_ptr(),
        ..Default::default()
    };

    let result = unsafe { func(*guid, &settings) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

fn set_via_registry(guid: &GUID, dns_servers: &[IpAddr]) -> io::Result<()> {
    let guid_str = format_guid(guid);
    let (v4, v6) = split_by_family(dns_servers);

    let key_for = |stack: &str| {
        format!("SYSTEM\\CurrentControlSet\\Services\\{stack}\\Parameters\\Interfaces\\{guid_str}")
    };

    if !v4.is_empty() {
        write_nameserver_registry(&key_for("Tcpip"), &dns_to_comma_separated(&v4))?;
    }

    if !v6.is_empty() {
        write_nameserver_registry(&key_for("Tcpip6"), &dns_to_comma_separated(&v6))?;
    }

    notify_dnscache()?;
    if let Err(e) = flush_resolver_cache() {
        log::debug!("DnsFlushResolverCache failed: {e}");
    }

    Ok(())
}

fn flush_resolver_cache() -> io::Result<()> {
    let lib = LibraryHandle::load("dnsapi.dll")
        .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;

    type FlushFn = unsafe extern "system" fn() -> u32;
    let func: FlushFn = unsafe {
        let proc = GetProcAddress(lib.0, c"DnsFlushResolverCache".as_ptr().cast())
            .ok_or_else(|| io::Error::from(io::ErrorKind::Unsupported))?;
        std::mem::transmute::<_, FlushFn>(proc)
    };

    if unsafe { func() } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn write_nameserver_registry(key_path: &str, name_server: &str) -> io::Result<()> {
    let key_wide = to_wide_null(key_path);
    let value_wide = to_wide_null("NameServer");
    let data_wide = to_wide_null(name_server);

    unsafe {
        let mut hkey = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            key_wide.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let byte_len = (data_wide.len() * 2) as u32;
        let status = RegSetValueExW(
            hkey,
            value_wide.as_ptr(),
            0,
            REG_SZ,
            data_wide.as_ptr().cast(),
            byte_len,
        );
        RegCloseKey(hkey);

        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

fn notify_dnscache() -> io::Result<()> {
    unsafe {
        let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if scm.is_null() {
            return Err(io::Error::last_os_error());
        }

        let svc = OpenServiceW(
            scm,
            to_wide_null("Dnscache").as_ptr(),
            SERVICE_PAUSE_CONTINUE,
        );
        if svc.is_null() {
            let err = io::Error::last_os_error();
            CloseServiceHandle(scm);
            return Err(err);
        }

        let mut status: SERVICE_STATUS = std::mem::zeroed();
        let ok = ControlService(svc, SERVICE_CONTROL_PARAMCHANGE, &mut status);
        let result = if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        };

        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        result
    }
}

fn set_via_netsh(adapter_name: &str, dns_servers: &[IpAddr]) -> io::Result<()> {
    let (v4, v6) = split_by_family(dns_servers);
    if !v4.is_empty() {
        apply_netsh_family(adapter_name, "ipv4", &v4)?;
    }
    if !v6.is_empty() {
        apply_netsh_family(adapter_name, "ipv6", &v6)?;
    }
    Ok(())
}

fn apply_netsh_family(adapter_name: &str, family: &str, servers: &[IpAddr]) -> io::Result<()> {
    let name = format!("name=\"{adapter_name}\"");
    let first_addr = format!("address=\"{}\"", servers[0]);
    run_netsh(&[
        "interface",
        family,
        "set",
        "dns",
        &name,
        "source=\"static\"",
        &first_addr,
    ])?;

    for (i, dns) in servers.iter().skip(1).enumerate() {
        let addr = format!("address=\"{dns}\"");
        let idx = format!("index={}", i + 2);
        if let Err(e) = run_netsh(&["interface", family, "add", "dns", &name, &idx, &addr]) {
            log::warn!("netsh add dns {dns} failed: {e}");
        }
    }
    Ok(())
}

fn run_netsh(args: &[&str]) -> io::Result<()> {
    let output = Command::new("netsh").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(stderr.to_string()));
    }
    Ok(())
}

fn split_by_family(dns_servers: &[IpAddr]) -> (Vec<IpAddr>, Vec<IpAddr>) {
    dns_servers.iter().partition(|ip| ip.is_ipv4())
}

fn is_valid_adapter_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c == '"' || c == '\'' || c.is_control())
}

fn format_guid(g: &GUID) -> String {
    let d = g.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
    )
}

fn dns_to_comma_separated(dns_servers: &[IpAddr]) -> String {
    dns_servers
        .iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn to_wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
