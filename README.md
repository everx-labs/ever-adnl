# ADNL

ADNL protocol stack implementation (UDP & TCP), including:
- ADNL (Abstract Datagram Network Layer) itself
- RLDP (Reliable Large Datagram Protocol)
- Overlay protocol

## Table of Contents

- [About](#about)
- [Getting Started](#getting-started)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)

## About

Implementation of Abstract Datagram Network Layer (ADNL) protocol stack in safe Rust. ADNL is a protocol layer that provides all low level communications between Everscale/Venom blockshain nodes. Depending on scenario, ADNL can operate on top of UDP or TCP protocols. 

Stack implementation includes several other protocols accompanying ADNL in node operation. Specifically:
- Reliable Large Datagram Protocol (RLDP). RLDP is a protocol that runs on top of ADNL UDP, which is used to transfer large data blocks and includes Forward Error Correction (FEC) algorithms as a replacement of acknowledgment packets on the other side. This makes it possible to transfer data between network components more efficiently, but with more traffic consumption.
- Overlay protocol. This protocol runs on top of ADNL UDP, and it is responsible for dividing a single network into additional subnetworks (overlays). Overlays can be both public, to which anyone can connect, and private, where additional credentials is needed for entry, known only to a certain amount of participants.

## Getting Started

### Prerequisites

Rust complier v1.76+.

### Installing

```
git clone --recurse-submodules https://github.com/tonlabs/ever-adnl.git
cd ever-adnl
cargo build --release
```

## Usage

This project output is the library which is used as a part of Everscale/Venom node. Also it can be used in standalone tools.

## Contributing

Contribution to the project is expected to be done via pull requests submission.

## License

See the [LICENSE](LICENSE) file for details.

## Tags

`blockchain` `everscale` `rust` `venom-blockchain` `venom-developer-program` `venom-network` 
