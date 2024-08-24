use clap::{Parser, Subcommand};
use pcap::Device;
use std::path::Path;
use tabled::settings::Style;
use tabled::{Table, Tabled};

use crate::replay::PcapHandler;

mod replay;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    cmd: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// About
    About,
    /// Version
    Version,
    /// Replay a pcap file
    Replay {
        #[arg(short, long, required = true)]
        /// The network interface to use
        interface: String,

        #[arg(short, long, default_value = "false")]
        /// Replay without the recorded delay between packets
        fast: bool,

        #[arg(short, long, required = true)]
        /// Pcap file to replay
        pcap: String,
    },
    /// List all network interfaces
    List {
        #[arg(short, long, default_value = "false")]
        /// Show network interface name, description and address
        full_info: bool,
    }, // /// Unsupported command
       // Gui,
}

#[derive(Tabled)]
struct Interface {
    name: String,
    description: String,
    address: String,
}

fn main() {
    // let pb = indicatif::ProgressBar::new(100);
    // for i in 0..100 {
    //     sleep(std::time::Duration::from_millis(1000));
    //     pb.println(format!("[+] finished #{}", i));
    //     pb.inc(1);
    // }
    // pb.finish_with_message("done");

    let args = Args::parse();
    match args.cmd {
        SubCommand::About => {
            println!("About");
        }
        SubCommand::Version => {
            println!("Version");
        }
        SubCommand::Replay {
            interface,
            fast,
            pcap,
        } => {
            //todo: debug logs

            // should call the replay function
            println!(
                "Replay: interface={}, fast={}, pcap={}",
                interface, fast, pcap
            );

            if interface.is_empty() {
                println!("You need to provide an interface name!");
                return;
            }
            if pcap.is_empty() {
                println!("You need to provide a pcap file!");
                return;
            }

            let pcap_path = Path::new(&pcap);
            if !pcap_path.exists() || !pcap_path.is_file() {
                println!("The given path is not a file or does not exist!");
                return;
            }

            let mut pcap_handler = PcapHandler::new();
            pcap_handler.replay(pcap_path, &interface, fast);
        }
        SubCommand::List { full_info } => {
            print_interfaces(full_info);
        }
    }
}

fn print_interfaces(full_info: bool) {
    let mut interfaces = Vec::new();
    let devices = Device::list().expect("Device lookup failed");

    if full_info {
        for device in devices {
            let mut interface = Interface {
                name: device.name,
                description: device.desc.unwrap_or(String::new()),
                address: String::new(),
            };
            if !device.addresses.is_empty() {
                interface.address = device.addresses[0].addr.to_string();
            }
            interfaces.push(interface);
        }
        let mut table = Table::new(&interfaces);
        table.with(Style::modern());
        println!("{table}");
    } else {
        for device in devices {
            println!("{}", device.name);
        }
    }
}
