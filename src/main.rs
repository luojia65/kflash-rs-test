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
            let ans = process_seiral_port(&info.port_name);
            if let Err(e) = ans {
                println!("Process serial port error: {:?}", e);
            } 
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
    a.set_timeout(core::time::Duration::from_secs_f32(2.0))?;
    // println!("{:?}", a.timeout());
    // println!("{:?}", a.settings());

    reset_isp_mode(a.as_mut())?;

    greeting(a.as_mut())?;

    flash_dataframe(a.as_mut(), STAGE_1_BIN, STAGE_1_BASE)?;

    println!("Write stage 1 finished");

    Ok(())
}

fn reset_isp_mode(serial: &mut dyn SerialPort) -> serialport::Result<()> {
    println!("Reset to ISP mode");
    // boot: LOW, reset: LOW
    serial.write_data_terminal_ready(false)?;
    serial.write_request_to_send(false)?;
    std::thread::sleep(core::time::Duration::from_secs_f32(0.1));
    // boot: HIGH
    serial.write_data_terminal_ready(true)?;
    serial.write_request_to_send(false)?;
    std::thread::sleep(core::time::Duration::from_secs_f32(0.1));
    // reset: HIGH
    serial.write_data_terminal_ready(false)?; 
    serial.write_request_to_send(true)?;
    std::thread::sleep(core::time::Duration::from_secs_f32(0.1));
    Ok(())
}

fn greeting(serial: &mut dyn SerialPort) -> serialport::Result<()> {
    println!("Write greeting");
    serial.write(GREETING)?;
    let greeting_answer = recv_one_return(serial)?;
    println!("Greeting answer: {:?}", greeting_answer);
    Ok(())
}

fn flash_dataframe(serial: &mut dyn SerialPort, data: &[u8], base_addr: u64) -> serialport::Result<()> {
    println!("Begin flash dataframe");
    let mut address = base_addr;
    for chunk in data.chunks(DATAFRAME_SIZE) {
        println!("Begin write addr 0x{:08X}", address);
        let mut out = BytesMut::with_capacity(2 + 2 + 4 + 4 + 4 + chunk.len());
        let mut digest = crc32::Digest::new(crc32::IEEE);
        digest.write(&(address as u32).to_le_bytes());
        digest.write(&(chunk.len() as u32).to_le_bytes());
        digest.write(chunk);
        let checksum = digest.sum32();
        println!("Checksum: {:08x}", checksum);
        out.put_u16_le(0x00C3);
        out.put_u16_le(0x0000);
        out.put_u32_le(checksum);
        out.put_u32_le(address as u32);
        out.put_u32_le(chunk.len() as u32);
        out.put_slice(chunk);
        
        println!("{}", out.len());
        println!("{:?}", out);

        address += chunk.len() as u64;
        loop {
            serial.write(&out)?;
            serial.flush()?;
            let received = receive_debug(serial);
            println!("Received {:?}", received);
            if let Ok(true) = received {
                break;
            }
        }
    }
    Ok(())
}

fn receive_debug(serial: &mut dyn SerialPort) -> serialport::Result<bool> {
    let one_return = recv_one_return(serial)?;
    let op = one_return[0];
    let reason = one_return[1];
    println!("Return op: 0x{:02X}", op);
    println!("ISP response: 0x{:02X}", reason);
    if reason != 0x00 && reason != 0xE0 {
        println!("ISP return check failed!");
        return Ok(false);
    }
    return Ok(true);
}

fn recv_one_return(serial: &mut dyn SerialPort) -> serialport::Result<Vec<u8>> {
    let mut recv = [0u8; 1];
    while recv[0] != 0xC0 {
        let _len = serial.read(&mut recv)?;
        println!("Receive: 0x{:02X}", recv[0]); // trace
    }
    let mut recv = [0u8; 1];
    let mut ans: Vec<u8> = Vec::new();
    let mut in_escape = false;
    loop {
        let _len = serial.read(&mut recv)?;
        if recv[0] == 0xC0 {
            break
        } else if in_escape {
            in_escape = false;
            if recv[0] == 0xDC {
                ans.push(0xC0);
            } else if recv[0] == 0xDD {
                ans.push(0xDB);
            } else {
                panic!("Invalid SLIP escape!")
            }
        } else if recv[0] == 0xDB {
            in_escape = true;
        }
        ans.push(recv[0]);
    }
    print!("Receive one: ");
    for i in &ans {
        print!("0x{:02X} ", i);
    }
    println!();
    Ok(ans)
}
