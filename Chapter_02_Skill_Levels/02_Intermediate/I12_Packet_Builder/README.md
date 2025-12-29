# I12 Packet Builder

A comprehensive tool for building and analyzing custom network packets.

## Overview

Understanding packet structure is fundamental for security research, network analysis, and penetration testing. This tool provides:

- Building Ethernet, IPv4, TCP, UDP, ICMP packets
- Analyzing packet hex dumps
- Calculating checksums
- Generating test packets for fuzzing

## Features

### Packet Construction
Build packets layer by layer or as complete stacks.

### Packet Analysis
Parse hex dumps to understand packet structure.

### Fuzzing Support
Generate random packets for protocol testing.

### Checksum Calculation
Calculate various protocol checksums.

## Usage

```bash
# Build the project
cargo build --release

# Build Ethernet frame
cargo run -- ethernet --src "00:11:22:33:44:55" --dst "ff:ff:ff:ff:ff:ff"

# Build IPv4 packet
cargo run -- ipv4 --src "192.168.1.1" --dst "192.168.1.2" --protocol tcp

# Build TCP segment
cargo run -- tcp --src-port 12345 --dst-port 80 --flags "syn"

# Build TCP SYN/ACK
cargo run -- tcp --src-port 80 --dst-port 12345 --flags "syn,ack"

# Build UDP datagram
cargo run -- udp --src-port 12345 --dst-port 53 --payload "query"

# Build ICMP echo request
cargo run -- icmp --icmp-type echo-request --id 1 --seq 1

# Build complete TCP/IP packet
cargo run -- full --src-ip 192.168.1.1 --dst-ip 192.168.1.2 \
    --src-port 12345 --dst-port 80 --flags syn

# Analyze packet hex dump
cargo run -- analyze "450000280001..." --packet-type ipv4

# Generate fuzz packets
cargo run -- fuzz --packet-type tcp --count 10

# Calculate checksum
cargo run -- checksum "450000280001..." --checksum-type ip
```

## Commands

| Command | Description |
|---------|-------------|
| `ethernet` | Build Ethernet frame |
| `ipv4` | Build IPv4 packet |
| `tcp` | Build TCP segment |
| `udp` | Build UDP datagram |
| `icmp` | Build ICMP packet |
| `full` | Build complete TCP/IP packet |
| `analyze` | Analyze packet from hex |
| `fuzz` | Generate random packets |
| `checksum` | Calculate checksum |

## TCP Flags

Available TCP flags:
- `syn` - Synchronize
- `ack` - Acknowledgment
- `fin` - Finish
- `rst` - Reset
- `psh` - Push
- `urg` - Urgent
- `ece` - ECN-Echo
- `cwr` - Congestion Window Reduced

Combine with commas: `--flags "syn,ack"`

## Security Applications

- **Protocol Testing**: Craft specific packets for testing
- **IDS/IPS Testing**: Generate edge-case packets
- **Network Debugging**: Analyze captured traffic
- **Fuzzing**: Generate malformed packets

## Dependencies

- `pnet` - Packet manipulation
- `clap` - CLI parsing
- `hex` - Hex encoding
- `serde` - Serialization

## Note

Sending raw packets requires root/administrator privileges. This tool focuses on packet construction and analysis.

## Testing

```bash
cargo test
```

## License

MIT
