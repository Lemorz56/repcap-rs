use std::path::Path;
use pcap::{Active, Capture, Device, Packet};
use std::time::{Duration, Instant};
use std::thread::sleep;
use libc::timeval;
use log::error;

pub struct PcapHandler {
    last_time_sent: Option<Instant>,
    last_ts: Option<timeval>,
    start: Option<Instant>,
    pkt: usize,
}

impl PcapHandler {
    pub fn new() -> Self {
        PcapHandler {
            last_time_sent: None,
            last_ts: None,
            start: None,
            pkt: 0,
        }
    }

    pub fn replay(&mut self, filename: &Path, net_intf: &str, fast: bool) {
        let mut capture = Capture::from_file(filename).expect("Error opening pcap file");
        self.start = Some(Instant::now());
        self.pkt = 0;

        let mut target_capture = Self::open_target(net_intf);

        if fast {
            loop {
                let packet = match capture.next_packet() {
                    Ok(packet) => packet,
                    Err(pcap::Error::NoMorePackets) => break,
                    Err(e) => {
                        error!("Failed to read packet {}: {}", self.pkt, e);
                        break;
                    }
                };
                Self::write_packet(&mut target_capture, &packet);
                self.pkt += 1;
            }
        } else {
            loop {

                let packet = match capture.next_packet() {
                    Ok(packet) => packet,
                    Err(pcap::Error::NoMorePackets) => break,
                    Err(e) => {
                        error!("Failed to read packet {}: {}", self.pkt, e);
                        break;
                    }
                };
                self.write_packet_delayed(&mut target_capture, &packet);
                self.pkt += 1;
            }
        }
        println!("Replay finished, wrote {} packets", self.pkt);
    }

    // fn load_pcap(&mut self, filename: &str) -> Capture<Offline> {
    //     // self.pcap_handle =
    //     self.start = Some(Instant::now());
    //     self.pkt = 0;
    //     Capture::from_file(filename).expect("Error opening pcap file")
    // }

    fn open_target(net_intf: &str) -> Capture<Active> {
        let device = Device::list()
            .expect("Error finding devices")
            .into_iter()
            .find(|d| d.name == net_intf)
            .unwrap_or_else(|| panic!("Error finding device called {}", net_intf));

        let cap = Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .open();

        match cap {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to open device: {}", e);
                std::process::exit(1);
            }
        }
    }

    // fn next_packet(capture: Capture<Offline>) -> Option<Packet> {
    //     if let Some(ref mut handle) = capture {
    //         match handle.next_packet() {
    //             Ok(packet) => Some(packet),
    //             Err(pcap::Error::NoMorePackets) => None,
    //             Err(e) => {
    //                 error!("Failed to read packet {}: {}", self.pkt, e);
    //                 None
    //             }
    //         }
    //     } else {
    //         None
    //     }
    // }

    fn write_packet_delayed(&mut self, handle: &mut Capture<Active>, packet: &Packet) {
        if let Some(last_ts) = self.last_ts {
            let interval_in_capture = Self::timeval_to_duration(packet.header.ts) - Self::timeval_to_duration(last_ts);
            if let Some(last_time_sent) = self.last_time_sent {
                let elapsed_time = last_time_sent.elapsed();
                if interval_in_capture > elapsed_time {
                    sleep(interval_in_capture - elapsed_time);
                }
            }
        }

        self.last_time_sent = Some(Instant::now());
        Self::write_packet(handle, packet);
        self.last_ts = Some(packet.header.ts);
    }

    fn write_packet(handle: &mut Capture<Active>, packet: &Packet) {
        if let Err(e) = handle.sendpacket(packet.data) {
            error!("Failed to send packet: {}", e);
        }
    }

    fn timeval_to_duration(tv: timeval) -> Duration {
        Duration::new(tv.tv_sec as u64, (tv.tv_usec * 1000) as u32)
    }
}