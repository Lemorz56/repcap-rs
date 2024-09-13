use libc::timeval;
use log::error;
use pcap::{Active, Capture, Device, Offline, Packet};
use std::{
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};
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

        let process_packet = if fast {
            |handler: &mut PcapHandler, target_capture: &mut Capture<Active>, packet: &Packet| {
                //todo: use handler.write_packet instead of Self::
                handler.write_packet(target_capture, packet);
            }
        } else {
            |handler: &mut PcapHandler, target_capture: &mut Capture<Active>, packet: &Packet| {
                handler.write_packet_delayed(target_capture, packet);
            }
        };

        self.process_packets(&mut capture, &mut target_capture, process_packet);
        println!("Replay finished, wrote {} packets", self.pkt);
    }

    fn open_target(net_intf: &str) -> Capture<Active> {
        let device = Device::list()
            .expect("Error finding devices")
            .into_iter()
            .find(|d| d.name == net_intf)
            .unwrap_or_else(|| panic!("Error finding device called {}", net_intf));

        Capture::from_device(device)
            .and_then(|c| c.open())
            .unwrap_or_else(|e| {
                error!("Failed to open device: {}", e);
                std::process::exit(1);
            })
    }

    fn write_packet_delayed(&mut self, handle: &mut Capture<Active>, packet: &Packet) {
        if let Some(last_ts) = self.last_ts {
            let interval_in_capture =
                Self::timeval_to_duration(packet.header.ts) - Self::timeval_to_duration(last_ts);
            if let Some(last_time_sent) = self.last_time_sent {
                let elapsed_time = last_time_sent.elapsed();
                if interval_in_capture > elapsed_time {
                    sleep(interval_in_capture - elapsed_time);
                }
            }
        }

        self.last_time_sent = Some(Instant::now());
        self.write_packet(handle, packet);
        self.last_ts = Some(packet.header.ts);
    }

    fn write_packet(&mut self, handle: &mut Capture<Active>, packet: &Packet) {
        if let Err(e) = handle.sendpacket(packet.data) {
            error!("Failed to send packet: {}", e);
        }
    }

    fn process_packets<F>(
        &mut self,
        capture: &mut Capture<Offline>,
        target_capture: &mut Capture<Active>,
        mut process_packet_func: F,
    ) where
        F: FnMut(&mut PcapHandler, &mut Capture<Active>, &Packet),
    {
        // TODO: find out max packet count
        // let pb = indicatif::ProgressBar::new(capture.total);

        println!("Processing packets...");
        // let mut stdlock = stdout().lock();
        loop {
            let packet = match capture.next_packet() {
                Ok(packet) => packet,
                Err(pcap::Error::NoMorePackets) => break,
                Err(e) => {
                    error!("Failed to read packet {}: {}", self.pkt, e);
                    break;
                }
            };
            process_packet_func(self, target_capture, &packet);
            self.pkt += 1;
            print!("[+]");
            // pb.println(format!("[+] finished #{}", self.pkt));
            // pb.inc(1);
        }
        // pb.finish_with_message("Done!");
        println!()
    }
    fn timeval_to_duration(tv: timeval) -> Duration {
        Duration::new(tv.tv_sec as u64, (tv.tv_usec * 1000) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_replay_fast() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.pcap");
        let mut file = File::create(&file_path).unwrap();

        let pcap_header = [
            0xd4, 0xc3, 0xb2, 0xa1, // Magic number
            0x02, 0x00, // Major version number
            0x04, 0x00, // Minor version number
            0x00, 0x00, 0x00, 0x00, // GMT to local correction
            0x00, 0x00, 0x00, 0x00, // Accuracy of timestamps
            0xff, 0xff, 0x00, 0x00, // Max length of captured packets, in octets
            0x01, 0x00, 0x00, 0x00, // Data link type
        ];
        let packet_header = [
            0x00, 0x00, 0x00, 0x00, // Timestamp seconds
            0x00, 0x00, 0x00, 0x00, // Timestamp microseconds
            0x04, 0x00, 0x00, 0x00, // Number of octets of packet saved in file
            0x04, 0x00, 0x00, 0x00, // Actual length of packet
        ];
        let packet_data = [0xde, 0xad, 0xbe, 0xef]; // Mock packet data

        file.write_all(&pcap_header).unwrap();
        file.write_all(&packet_header).unwrap();
        file.write_all(&packet_data).unwrap();

        let devices = Device::list().expect("Error finding devices");
        let device_name = devices
            .first()
            .expect("No network devices found")
            .name
            .clone();

        let mut handler = PcapHandler::new();
        handler.replay(&file_path, &device_name, true);

        assert_eq!(handler.pkt, 1);
    }

    #[test]
    fn test_replay_delayed() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.pcap");
        let mut file = File::create(&file_path).unwrap();

        let pcap_header = [
            0xd4, 0xc3, 0xb2, 0xa1, // Magic number
            0x02, 0x00, // Major version number
            0x04, 0x00, // Minor version number
            0x00, 0x00, 0x00, 0x00, // GMT to local correction
            0x00, 0x00, 0x00, 0x00, // Accuracy of timestamps
            0xff, 0xff, 0x00, 0x00, // Max length of captured packets, in octets
            0x01, 0x00, 0x00, 0x00, // Data link type
        ];
        let packet_header = [
            0x00, 0x00, 0x00, 0x00, // Timestamp seconds
            0x00, 0x00, 0x00, 0x00, // Timestamp microseconds
            0x04, 0x00, 0x00, 0x00, // Number of octets of packet saved in file
            0x04, 0x00, 0x00, 0x00, // Actual length of packet
        ];
        let packet_data = [0xde, 0xad, 0xbe, 0xef]; // Mock packet data

        file.write_all(&pcap_header).unwrap();
        file.write_all(&packet_header).unwrap();
        file.write_all(&packet_data).unwrap();

        let devices = Device::list().expect("Error finding devices");
        let device = devices
            .first()
            .expect("No network devices found")
            .name
            .clone();

        let mut handler = PcapHandler::new();
        handler.replay(&file_path, &device, false);

        assert_eq!(handler.pkt, 1);
    }

    #[test]
    fn test_timeval_to_duration() {
        let timeval = timeval {
            tv_sec: 1,
            tv_usec: 500000,
        };
        let duration = PcapHandler::timeval_to_duration(timeval);
        assert_eq!(duration.as_secs(), 1);
        assert_eq!(duration.subsec_micros(), 500000);
    }

    #[test]
    fn test_write_packet_delayed_with_last_time_sent() {
        let mut handler = PcapHandler::new();
        handler.last_ts = Some(timeval {
            tv_sec: 1,
            tv_usec: 0,
        });
        handler.last_time_sent = Some(Instant::now() - Duration::from_secs(1));

        let devices = Device::list().expect("Error finding devices");
        let device = devices.first().expect("No network devices found").clone();

        let mut capture = Capture::from_device(device).unwrap().open().unwrap();
        let packet = Packet {
            header: &pcap::PacketHeader {
                ts: timeval {
                    tv_sec: 2,
                    tv_usec: 0,
                },
                caplen: 4,
                len: 4,
            },
            data: &[0xde, 0xad, 0xbe, 0xef],
        };

        handler.write_packet_delayed(&mut capture, &packet);

        assert!(handler.last_time_sent.is_some());
        assert_eq!(handler.last_ts.unwrap().tv_sec, 2);
    }
}
