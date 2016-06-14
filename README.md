# librips testsuite

This is a small tool for using the functionality of the Rust TCP/IP stack
implementation [librips](https://github.com/faern/librips).

# Usage

Clone [librips](https://github.com/faern/librips) and this repo next to each
other.
Run `cargo run -- help` for usage instructions.

```bash
git clone https://github.com/faern/librips
git clone https://github.com/faern/ripstest
cd ripstest
cargo run -- help
```

Will print something like:

```bash
RIPS testsuite 1.0
Linus Färnstrand <faern@faern.net>
Test out the RIPS TCP/IP stack in the real world

USAGE:
    ripstest [FLAGS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -v               Sets the level of verbosity
    -V, --version    Prints version information

SUBCOMMANDS:
    arp     Send an Arp query to the network and wait for the response
    eth     Sends raw ethernet frames to a given MAC address.
    help    Prints this message or the help of the given subcommand(s)
    ipv4    Send an IPv4 packet with a given payload to the network.
```
