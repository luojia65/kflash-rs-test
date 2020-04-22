use serialport::SerialPortType::*;
use serialport::prelude::*;
use bytes::{BytesMut, BufMut};
use crc::{crc32, Hasher32};

const GREETING: &[u8] = &[
    0xC0, 0xC2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0
];
const STAGE_1_BASE: u64 = 0x80000000;
const STAGE_1_BIN: &[u8] = include_bytes!("stage1.bin");
const DATAFRAME_SIZE: usize = 1024;

fn main() -> serialport::Result<()> {
    for info in serialport::available_ports()? {
        println!("{:?}", info);
        if let UsbPort(usb) = info.port_type {
            if usb.vid != 0x0403 || usb.pid != 0x6010 {
                continue;
            }
            process_seiral_port(&info.port_name)?;
        }
    }
    // println!("Hello, world!");
    Ok(())
}

fn process_seiral_port(port_name: &str) -> serialport::Result<()> {
    let mut a = serialport::open(port_name)?;
    // println!("{:?}", a.name());

    a.set_baud_rate(115200)?;
    a.set_data_bits(DataBits::Eight)?;
    a.set_parity(Parity::None)?;
    a.set_stop_bits(StopBits::One)?;
    a.set_timeout(core::time::Duration::from_secs_f32(1.0))?;
    // println!("{:?}", a.timeout());
    // println!("{:?}", a.settings());

    a.write_request_to_send(false)?;
    a.write_data_terminal_ready(false)?;
    std::thread::sleep(core::time::Duration::from_secs_f32(0.1));
    a.write_data_terminal_ready(true)?;
    std::thread::sleep(core::time::Duration::from_secs_f32(0.1));
    a.write_data_terminal_ready(false)?;
    std::thread::sleep(core::time::Duration::from_secs_f32(0.1));

    a.write(GREETING)?;
    a.flush()?;
    std::thread::sleep(core::time::Duration::from_secs_f32(0.1));
    let mut recv = [0]; // 1 byte
    let ans = a.read(&mut recv);
    if let Err(e) = ans {
        // println!("Error occurred");
        return Err(e.into());
    }
    println!("Answer: 0x{:X}", recv[0]);

    flash_dataframe(a.as_mut(), STAGE_1_BIN, STAGE_1_BASE)?;

    println!("Write stage 1 finished");
    
    Ok(())
}

fn flash_dataframe(serial: &mut dyn SerialPort, data: &[u8], base_addr: u64) -> serialport::Result<()> {
    let mut address = base_addr;
    for chunk in data.chunks(DATAFRAME_SIZE) {
        let mut out = BytesMut::with_capacity(2 + 2 + 4 + 4 + 4 + chunk.len());
        let mut digest = crc32::Digest::new(crc32::IEEE);
        digest.write(&(address as u32).to_le_bytes());
        digest.write(&(chunk.len() as u32).to_le_bytes());
        digest.write(chunk);
        let checksum = digest.sum32();
        out.put_u16_le(0x00C3);
        out.put_u16_le(0x0000);
        out.put_u32_le(checksum);
        out.put_u32_le(address as u32);
        out.put_u32_le(chunk.len() as u32);
        out.put_slice(chunk);
        address += chunk.len() as u64;
        loop {
            println!("Write addr 0x{:08X}", address);
            serial.write(&out)?;
            if let Ok(()) = receive_debug(serial) {
                break;
            }
        }
    }
    Ok(())
}

fn receive_debug(serial: &mut dyn SerialPort) -> serialport::Result<()> {
    let mut recv = [0]; // 1 byte
    let ans = serial.read(&mut recv)?;
    let _ = ans; // todo: unused
    Ok(())
}
