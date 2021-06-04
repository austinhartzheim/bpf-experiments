# BPF Experiments
*Experimenting with BPF/XDP in Rust.*

## Features
* eBPF probe to count packets by the IPv4 `src` IP address and `dst` IP addresses.
* Userspace program to output packet counts from maps shared with the eBPF probe.
* Userspace program to block `src` IP addresses and list blocked IP addresses.
* Unix socket interface to list IPs/counts and to add blocks.

## Code Layout
```
kernelspace/
  Cargo.toml
  src/
    probe/
      main.rs       # Primary XDP functionality
      mod.rs        # Types shared between XDP and userspace
userspace/          # Userspace application
  Cargo.toml     
  src/
    control.rs      # Unix socket control port
    main.rs         # eBPF initialization and map access
```

## Choice of technologies
* [Rust](https://www.rust-lang.org/)
  * Allows writing the eBPF program and userspace program in the same language. Other projects are either developed entirely in C/C++, or mix C eBPF code with a memory safe language for userspace. Rust is a memory safe language, but it is also able to integrate with C ABIs making it an excellent to reduce the number of languages in the project.
  * Additionally, using the same language allows code to be shared across kernelspace and userspace. Sharing code in this way reduces bugs because it is not required to continuously integrate two implementations against each other. Even in this small project, we are sharing code to ensure that IP addresses are correctly converted to the network byte-order whenever they cross the userspace->kernelspace boundary. (More details in `kernelspace/src/probe/mod.rs`.)
* [Redbpf](https://github.com/foniod/redbpf)
  * Redbpf is an eBPF library for Rust. [Ingraind](https://ingraind.org/), a CNCF sandbox container security agent, is one of the largest public users of the library.
* Other:
  * This project also uses [`tokio`](https://tokio.rs/) as its asynchronous runtime for managing concurrent control socket connections. And, [`clap`](https://clap.rs/) is used to parse command line arguments. Both of these crates are prominent in the Rust ecosystem.

## Building the code
Two options are provided below: instructions for a plain Linux environment and instructions for building in a Docker image with the dependencies already installed.

### Building on Docker (Recommended)
1. Download a Docker image to use as a development environment. This image is populated with the dependencies to build eBPF programs plus a number of command line utilities. (This image is intended to be used during development and therefore has more software installed than would be found in a typical Docker image.) Source code for the Docker image is [available here](https://gist.github.com/austinhartzheim/89c587533e7739a61aaa348ded513579).
  ```sh
  docker pull public.ecr.aws/t7j5h7s8/rust-redbpf:latest
  ```
2. If your Docker host is not using Linux 5.10 (the version from the Debain repos), you will need to [download](https://www.kernel.org/) and extract the version of the kernel used by your host. You can check the kernel version of your Docker host by running `docker run public.ecr.aws/t7j5h7s8/rust-redbpf:latest uname -r`.
3. Start a new docker container, mounting in the source code to build. Also, mount in the extracted kernel files if required. The code will be available in `/code` inside the container, and the kernel at `/kernel`. (Note: the container must be `--privileged` to use eBPF.)
  ```sh
  docker run --privileged -v /PATH/TO/bpf-experiments:/code -v /PATH/TO/EXTRACTED/linux-x.xx.xxx:/kernel -it public.ecr.aws/t7j5h7s8/rust-redbpf:latest bash
  ```
4. If you needed a different kernel version, you will need to `make prepare` the kernel. Instructions may vary slightly depending on the version, but in general, run these commands in the container shell:
  ```sh
  cd /kernel
  make menuconfig
  # Press "Ctrl+C" or navigate to "exit" in the graphical configuration builder, then select
  # "yes" to save the configuration.
  make prepare
  ```
5. Build the application. Inside the container shell, run the following commands:
  ```sh
  export KERNEL_SOURCE=/kernel
  cd /code/kernelspace/
  cargo test --features std
  cargo bpf build

  cd /code/userspace
  cargo build
  ```

See "Interacting with the application" below for instructions on running the application.

**Note:** when using Docker on a Mac, the containers are running in a virtual machine which limits the number of CPU cores and memory allocated to the container. It may be desirable to increase these allocations to reduce build times. Should you hit a memory limit, the build may fail; retrying the "cargo" steps may be sufficient to make incremental progress on the compilation.

### Building on Linux
#### Environment preparation
Install dependencies (tested on Debian 11):
* Add APT repos for LLVM 11. Debian-based systems can use the repos provided here: https://apt.llvm.org/
  Add the following lines to `/etc/apt/sources.list.d/llvm.list`:
  ```text
  deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye main
  deb-src http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye main
  deb http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-11 main
  deb-src http://apt.llvm.org/bullseye/ llvm-toolchain-bullseye-11 main
  ```
  Add the repo signing key and update the APT repos:
  ```sh
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key|sudo apt-key add -
  apt update
  ```
* Install LLVM11, Linux headers, and other requirements for `redbpf`.
  ```sh
  sudo apt-get -y install curl build-essential zlib1g-dev \
      llvm-11-dev libclang-11-dev linux-headers-$(uname -r)
  ```
* [Install Rust](https://www.rust-lang.org/learn/get-started):
  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source $HOME/.cargo/env # add `cargo` to `$PATH`; alternatively, restart the shell
  ```
* Install `cargo-bpf`:
  ```sh
  cargo install cargo-bpf
  ```

#### Development workflow
The general development workflow is as follows (assuming a Linux host where the above environment preparation has been completed). Extract the provided source code and build the XDP probe from the `kernelspace` directory and the userspace application from the `userspace` directory.

Changing the XDP probes:
```sh
cd kernelspace
cargo test --features std
cargo bpf build
```

Changing the userspace application:
```sh
cd userspace
cargo build
# Binary will be placed at ./target/debug/userspace
```

Clean build:
Run `cargo clean` in `userspace` and `kernelspace`. This is the same as running `rm -rf ./target` from those directories.

## Interacting with the application
For the following steps, you will need to execute multiple programs at once. You may wish to use `tmux`, `docker exec`, or move processes into the background to achieve this.

1. Start the userspace application, specifying which network interface to use. This command must be run as root and will continue to run while you execute the later commands.
  ```sh
  ./target/debug/userspace -i eth0
  ```
2. Generate network traffic.
  ```sh
  ping 1.1.1.1
  ```
3. Packet counts can be listed by connecting to the control socket and issuing the `list-src` command. We are using netcat to connect to the Unix socket.
  ```sh
  nc -U /tmp/control
  list-src
  ```
  ```sh
  nc -U /tmp/control
  list-dst
  ```
4. Block a source address:
  ```sh
  nc -U /tmp/control
  block-src 1.1.1.1
  ```
  and observe that ping stops receiving replies:
  ```sh
  ping 1.1.1.1
  ```

### List of commands
```
list-src                  # List packet counts by source IPv4 address
list-dst                  # List packet counts by destination IPv4 address
list-block-src            # List blocked source addresses
block-src <ipv4 address>  # Block an IPv4 source address
```
