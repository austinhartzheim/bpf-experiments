use clap::{App, Arg};
use redbpf::load::Loader;
use redbpf::xdp::Flags;
use redbpf::HashMap;
use tokio::sync::mpsc;

use kernelspace::probe::BeIpv4Addr;

mod control;
use control::Command;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ! {
    // Parse command line arguments
    let args = App::new("userspace")
        .arg(
            Arg::with_name("interface")
                .short("i")
                .long("interface")
                .help("name of the network interface to attach XDP probes to")
                .takes_value(true)
                .default_value("eth0"),
        )
        .get_matches();

    // We use the `include_bytes!` macro to include the compiled eBPF program into the binary.
    // `Loader::load` then parses the ELF and exposes the individual eBPF probes.
    let mut loaded = Loader::load(include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/probe/probe.elf",
    )))
    .expect("error loading BPF program");

    // Iterate over the XDP probes and attach them to the network interface.
    let iface = args.value_of("interface").unwrap();
    for xdp in loaded.xdps_mut() {
        println!("Attaching {} to {}", xdp.name(), iface);
        xdp.attach_xdp(iface, Flags::default()).expect(&format!(
            "failed to attach XDP program to interface {}",
            iface
        ));
    }

    // Create references to the eBPF maps.
    let src_packets = HashMap::<BeIpv4Addr, u32>::new(
        loaded
            .map("SRC_PACKETS")
            .expect("HashMap SRC_PACKETS not found"),
    )
    .expect("error creating HashMap in userspace");
    let dst_packets = HashMap::<BeIpv4Addr, u32>::new(
        loaded
            .map("DST_PACKETS")
            .expect("HashMap DST_PACKETS not found"),
    )
    .expect("error creating HashMap in userspace");
    let src_blocks = HashMap::<BeIpv4Addr, bool>::new(
        loaded
            .map("SRC_BLOCK")
            .expect("HashMap SRC_BLOCK not found"),
    )
    .expect("error creating HashMap in userspace");

    // Start accepting connections on our control socket.
    let (commands_tx, mut commands_rx) = mpsc::channel(512);
    tokio::spawn(async move {
        control::control_socket_accept_loop(commands_tx).await;
    });

    // Wait for commands to arrive in the `commands_rx` queue, process those commands, and send
    // replies on the oneshot channels.
    loop {
        let command_request = commands_rx.recv().await.expect("command channel closed");
        let res = match command_request.command {
            Command::ListSrcIps => command_request.reply.send(
                src_packets
                    .iter()
                    .fold(String::new(), |buf, (be_ip, count)| {
                        format!("{}{}\t{}\n", buf, be_ip.to_ip(), count)
                    }),
            ),
            Command::ListDstIps => command_request.reply.send(
                dst_packets
                    .iter()
                    .fold(String::new(), |buf, (be_ip, count)| {
                        format!("{}{}\t{}\n", buf, be_ip.to_ip(), count)
                    }),
            ),
            Command::ListBlockSrc => command_request.reply.send(
                src_blocks
                    .iter()
                    .fold(String::new(), |buf, (be_ip, count)| {
                        format!("{}{}\t{}\n", buf, be_ip.to_ip(), count)
                    }),
            ),
            Command::BlockSrc(ip) => {
                let be_ip = BeIpv4Addr::from(ip);
                src_blocks.set(be_ip, true);
                command_request.reply.send("ok\n".into())
            }
        };
        if let Err(e) = res {
            println!("error sending command reply: {:?}", e);
        }
    }
}
