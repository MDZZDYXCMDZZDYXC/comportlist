use std::ffi::{CStr, CString};
use std::{mem, ptr};

use winapi::shared::guiddef::*;
use winapi::shared::minwindef::*;
use winapi::shared::ntdef::CHAR;
use winapi::shared::winerror::*;
use winapi::um::cguid::GUID_NULL;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::setupapi::*;
use winapi::um::winnt::KEY_READ;
use winapi::um::winreg::*;

pub struct UsbPortInfo {
    /// Vendor ID
    pub vid: u16,
    /// Product ID
    pub pid: u16,
    /// Serial number (arbitrary string)
    pub serial_number: Option<String>,
    /// Manufacturer (arbitrary string)
    pub manufacturer: Option<String>,
    /// Product name (arbitrary string)
    pub product: Option<String>,
}
pub enum SerialPortType {
    /// The serial port is connected via USB
    UsbPort(UsbPortInfo),
    /// The serial port is connected via PCI (permanent port)
    PciPort,
    /// The serial port is connected via Bluetooth
    BluetoothPort,
    /// It can't be determined how the serial port is connected
    Unknown,
}
pub struct SerialPortInfo {
    /// The short name of the serial port
    pub port_name: String,
    /// The hardware device type that exposes this port
    pub port_type: SerialPortType,
}
pub fn add(left: usize, right: usize) -> usize {
    left + right
}

struct PortDevice {
    /// Handle to a device information set.
    hdi: HDEVINFO,

    /// Information associated with this device.
    pub devinfo_data: SP_DEVINFO_DATA,
}

impl PortDevice {
    // Retrieves the device instance id string associated with this device. Some examples of
    // instance id strings are:
    //  MicroPython Board:  USB\VID_F055&PID_9802\385435603432
    //  FTDI USB Adapter:   FTDIBUS\VID_0403+PID_6001+A702TB52A\0000
    //  Black Magic Probe (Composite device with 2 UARTS):
    //      GDB Port:       USB\VID_1D50&PID_6018&MI_00\6&A694CA9&0&0000
    //      UART Port:      USB\VID_1D50&PID_6018&MI_02\6&A694CA9&0&0002
    fn instance_id(&mut self) -> Option<String> {
        let mut result_buf = [0i8; MAX_PATH];
        let res = unsafe {
            SetupDiGetDeviceInstanceIdA(
                self.hdi,
                &mut self.devinfo_data,
                result_buf.as_mut_ptr(),
                (result_buf.len() - 1) as DWORD,
                ptr::null_mut(),
            )
        };
        if res == FALSE {
            // Try to retrieve hardware id property.
            self.property(SPDRP_HARDWAREID)
        } else {
            let end_of_buffer = result_buf.len() - 1;
            result_buf[end_of_buffer] = 0;
            Some(unsafe {
                CStr::from_ptr(result_buf.as_ptr())
                    .to_string_lossy()
                    .into_owned()
            })
        }
    }

    // Retrieves the port name (i.e. COM6) associated with this device.
    pub fn name(&mut self) -> String {
        let hkey = unsafe {
            SetupDiOpenDevRegKey(
                self.hdi,
                &mut self.devinfo_data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DEV,
                KEY_READ,
            )
        };
        let mut port_name_buffer = [0u8; MAX_PATH];
        let mut port_name_len = port_name_buffer.len() as DWORD;
        let value_name = CString::new("COM0COM").unwrap();//PortName
        unsafe {
            RegQueryValueExA(
                hkey,
                value_name.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                port_name_buffer.as_mut_ptr(),
                &mut port_name_len,
            )
        };
        unsafe { RegCloseKey(hkey) };

        let mut port_name = &port_name_buffer[0..port_name_len as usize];

        // Strip any nul bytes from the end of the buffer
        while port_name.last().map_or(false, |c| *c == b'\0') {
            port_name = &port_name[..port_name.len() - 1];
        }

        String::from_utf8_lossy(port_name).into_owned()
    }

    // Determines the port_type for this device, and if it's a USB port populate the various fields.
    pub fn port_type(&mut self) -> Option<UsbPortInfo> {
        if let Some(hardware_id) = self.instance_id() {
            println!("hardware_id:{}",hardware_id);
            return Some(UsbPortInfo {
                vid: 11,
                pid: 11,
                serial_number: {if let Some(ss) = self.property(SPDRP_FRIENDLYNAME){
                    let sslits = ss.split(" ").collect::<Vec<&str>>();
                    if sslits[sslits.len()-1].contains("COM"){
                        let comxx = sslits[sslits.len()-1].to_string().replace(")", "").replace("(", "");
                        Some(comxx)
                    }else{
                        None
                    }
                }else{
                    None
                }},// caps.get(4).map(|m| m.as_str().to_string()),
                manufacturer: self.property(SPDRP_MFG),
                product: self.property(SPDRP_FRIENDLYNAME),
            });
        }
        None
    }
    // Retrieves a device property and returns it, if it exists. Returns None if the property
    // doesn't exist.
    fn property(&mut self, property_id: DWORD) -> Option<String> {
        let mut result_buf: [CHAR; MAX_PATH] = [0; MAX_PATH];
        let res = unsafe {
            SetupDiGetDeviceRegistryPropertyA(
                self.hdi,
                &mut self.devinfo_data,
                property_id,
                ptr::null_mut(),
                result_buf.as_mut_ptr() as PBYTE,
                (result_buf.len() - 1) as DWORD,
                ptr::null_mut(),
            )
        };
        if res == FALSE {
            if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
                return None;
            }
        }
        let end_of_buffer = result_buf.len() - 1;
        result_buf[end_of_buffer] = 0;
        Some(unsafe {
            CStr::from_ptr(result_buf.as_ptr())
                .to_string_lossy()
                .into_owned()
        })
    }
}

fn get_ports_guids(serchkey:Vec<&str>) -> Option<Vec<GUID>> {
    // Note; unwrap can't fail, since "Ports" is valid UTF-8.//CNCPorts
    let mut allguid: Vec<GUID> = Vec::new();

    for idx in serchkey{
        let ports_class_name = CString::new(idx).unwrap();//Ports

        // Size vector to hold 1 result (which is the most common result).
        let mut num_guids: DWORD = 0;
        let mut guids: Vec<GUID> = Vec::new();
        guids.push(GUID_NULL); // Placeholder for first result

        // Find out how many GUIDs are associated with "Ports". Initially we assume
        // that there is only 1. num_guids will tell us how many there actually are.
        let res = unsafe {
            SetupDiClassGuidsFromNameA(
                ports_class_name.as_ptr(),
                guids.as_mut_ptr(),
                guids.len() as DWORD,
                &mut num_guids,
            )
        };
        if res == FALSE {
            println!("Unable to determine number of Ports GUIDs");
            return None;
        }
        if num_guids == 0 {
            // We got a successful result of no GUIDs, so pop the placeholder that
            // we created before.
            guids.pop();
        }

        if num_guids as usize > guids.len() {
            // It turns out we needed more that one slot. num_guids will contain the number of slots
            // that we actually need, so go ahead and expand the vector to the correct size.
            while guids.len() < num_guids as usize {
                guids.push(GUID_NULL);
            }
            let res = unsafe {
                SetupDiClassGuidsFromNameA(
                    ports_class_name.as_ptr(),
                    guids.as_mut_ptr(),
                    guids.len() as DWORD,
                    &mut num_guids,
                )
            };
            if res == FALSE {
                println!("Unable to retrieve Ports GUIDs");
                return None;
            }
        }
        allguid.append(&mut guids);
    }
    Some(allguid)
}

pub fn available_ports() -> Vec<UsbPortInfo> {
    let mut ports = Vec::new();
    if let Some(p_guid) = get_ports_guids(vec!["CNCPorts","Ports"]){
        for guid in p_guid {
            println!("--{}",guid.Data1);
            let port_devices = PortDevices::new(&guid);
            for mut port_device in port_devices {
                let port_name = port_device.name();
                println!("{}",port_name);
                debug_assert!(
                    port_name.as_bytes().last().map_or(true, |c| *c != b'\0'),
                    "port_name has a trailing nul: {:?}",
                    port_name
                );
                // This technique also returns parallel ports, so we filter these out.
                if port_name.starts_with("LPT") {
                    continue;
                }
                if let Some(pp) = port_device.port_type(){
                    ports.push(pp);
                }
            }
        }
    }
    
    ports
}

struct PortDevices {
    /// Handle to a device information set.
    hdi: HDEVINFO,

    /// Index used by iterator.
    dev_idx: DWORD,
}
impl PortDevices {
    // Creates PortDevices object which represents the set of devices associated with a particular
    // Ports class (given by `guid`).
    pub fn new(guid: &GUID) -> Self {
        PortDevices {
            hdi: unsafe { SetupDiGetClassDevsA(guid, ptr::null(), ptr::null_mut(), DIGCF_PRESENT) },
            dev_idx: 0,
        }
    }
}
impl Iterator for PortDevices {
    type Item = PortDevice;

    /// Iterator which returns a PortDevice from the set of PortDevices associated with a
    /// particular PortDevices class (guid).
    fn next(&mut self) -> Option<PortDevice> {
        let mut port_dev = PortDevice {
            hdi: self.hdi,
            devinfo_data: SP_DEVINFO_DATA {
                cbSize: mem::size_of::<SP_DEVINFO_DATA>() as DWORD,
                ClassGuid: GUID_NULL,
                DevInst: 0,
                Reserved: 0,
            },
        };
        let res =
            unsafe { SetupDiEnumDeviceInfo(self.hdi, self.dev_idx, &mut port_dev.devinfo_data) };
        if res == FALSE {
            None
        } else {
            self.dev_idx += 1;
            Some(port_dev)
        }
    }
}

impl Drop for PortDevices {
    fn drop(&mut self) {
        // Release the PortDevices object allocated in the constructor.
        unsafe {
            SetupDiDestroyDeviceInfoList(self.hdi);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
            for idx in available_ports(){
                if let Some(ss) = idx.serial_number{

                    println!("{}",ss);
                }
                if let Some(ss) = idx.product {
                    println!("{}",ss);
                }
                if let Some(ss) = idx.manufacturer{
                    println!("{}",ss);
                }
            }
       
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
