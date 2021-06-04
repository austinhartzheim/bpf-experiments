//! Unix socket control port.
//!
//! This module handles the control protocol, which accepts commands from a unix socket to list
//! the state of the eBPF maps and update the block list.
//!
//! # Order of events
//! Commands are processed asynchronously to allow multiple sockets to issue commands at once. The
//! flow of commands is as follows:
//! 1. A unix socket connection is accepted and a `ControlConnection` is created.
//! 2. A command is read from the socket and parsed into a `Command`.
//! 3. The `Command` is packaged into a `CommandRequest`, along with a oneshot channel. The
//!    oneshot channel is a single-use channel that is used to send a reply to the command.
//! 4. The `CommandRequest` is sent to the command queue for processing.
//! 5. The `CommandRequest` is read from the queue, executed, and a reply is sent to the oneshot
//!    channel.
//! 6. The reply is read from the oneshot channel and written to the Unix socket.
//! 7. The unix socket is closed.
//!
use std::error::Error;
use std::net::Ipv4Addr;
use std::path::Path;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

/// The set of commands that may be issued via the control socket.
///
/// Rust enums allow associated data with the variants (i.e., [sum types]), which is used here to
/// pass parameters to the processing task.
///
/// [sum types]: https://en.wikipedia.org/wiki/Algebraic_data_type
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    ListSrcIps,
    ListDstIps,
    ListBlockSrc,
    BlockSrc(Ipv4Addr),
}

#[derive(Debug)]
pub struct CommandRequest {
    pub command: Command,
    pub reply: oneshot::Sender<String>,
}

/// Bind a unix socket and accept connections in a loop. Spawn new task to process commands on
/// each connection.
pub async fn control_socket_accept_loop(commands_tx: mpsc::Sender<CommandRequest>) {
    // If the control socket already exists, delete it and re-create it.
    if Path::new("/tmp/control").exists() {
        std::fs::remove_file("/tmp/control").unwrap();
    }
    let control_socket = UnixListener::bind("/tmp/control").expect("failed to bind unix socket");

    loop {
        match control_socket.accept().await {
            Ok((stream, _addr)) => {
                println!("new control socket connection");
                let cloned_commands_tx = commands_tx.clone();
                tokio::spawn(async move {
                    println!(
                        "control socket closed: {:?}",
                        ControlConnection::new(stream, cloned_commands_tx)
                            .process_command()
                            .await
                    );
                });
            }
            Err(err) => {
                println!("control socket connection failed: {}", err);
            }
        }
    }
}

/// Holds state for a connection to the control socket.
pub struct ControlConnection {
    /// This channel is used to send commands to the main loop for processing.
    commands_tx: mpsc::Sender<CommandRequest>,
    /// The unix socket stream, used to receive control commands and write output.
    stream: BufStream<UnixStream>,
}

impl ControlConnection {
    /// Create a new `ControlConnection` for an accepted unix socket connection.
    pub fn new(stream: UnixStream, commands_tx: mpsc::Sender<CommandRequest>) -> Self {
        Self {
            commands_tx,
            stream: BufStream::new(stream),
        }
    }

    /// Read a single command from the unix socket, queue that command, and write any response to
    /// the control socket.
    pub async fn process_command(&mut self) -> Result<(), Box<dyn Error>> {
        let mut cmd_str = String::new();
        loop {
            // Read a line from the socket.
            cmd_str.clear();
            if self.stream.read_line(&mut cmd_str).await? == 0 {
                return Ok(()); // Reached EOF
            }
            let (cmd, params) = {
                // Remove trailing whitespace (likely `\r\n`).
                let cmd_slice = cmd_str.trim_end();
                let mut parts = cmd_slice.splitn(2, ' ');
                (parts.next().unwrap(), parts.next())
            };

            // Parse parameters and create `Command`
            let command = match (cmd, params) {
                ("list-src", None) => Command::ListSrcIps,
                ("list-dst", None) => Command::ListDstIps,
                ("list-block-src", None) => Command::ListBlockSrc,
                ("block-src", Some(ip)) => {
                    let parsed_ip = match ip.parse() {
                        Ok(parsed) => parsed,
                        Err(e) => {
                            self.stream
                                .write_all(format!("could not parse ip: {}\n", e).as_bytes())
                                .await?;
                            self.stream.flush().await?;
                            return Err("invalid ip address".into());
                        }
                    };
                    Command::BlockSrc(parsed_ip)
                }
                ("list-src", Some(_)) | ("list-dst", Some(_)) => {
                    self.stream.write_all(b"unexpected parameters\n").await?;
                    self.stream.flush().await?;
                    return Err("unexpected parameters".into());
                }
                ("block-src", None) => {
                    self.stream
                        .write_all(b"command requires parameters\n")
                        .await?;
                    self.stream.flush().await?;
                    return Err("command requires parameters".into());
                }
                (_, _) => {
                    self.stream.write_all(b"invalid command\n").await?;
                    self.stream.flush().await?;
                    return Err("invalid command".into());
                }
            };

            // Create a oneshot channel, issue the request, and write the reply to the socket.
            let (reply_tx, reply_rx) = oneshot::channel();
            self.commands_tx
                .send(CommandRequest {
                    command,
                    reply: reply_tx,
                })
                .await?;
            self.stream.write_all(reply_rx.await?.as_bytes()).await?;
            self.stream.flush().await?;

            // Currently, only one command may be issued for each connection. This eases parsing
            // of the response because there is no need to build specific mechanisms to separate
            // responses in the stream. (HAProxy behaves likewise for its control socket.)
            return Ok(());
        }
    }
}
