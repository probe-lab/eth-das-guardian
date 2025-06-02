# Eth DAS Guardian

The `eth-das-guardian` tool presented in this repo is an experimental, semi-standalone utility for assessing data-column custody in the [PeerDAS](https://eips.ethereum.org/EIPS/eip-7594) context. It logs and debugs all relevant information related to connecting to a remote node and verifying whether it retains and shares the data columns it claims custody of.

It can extract and present all available information for a given [ENR](https://github.com/ethereum/devp2p/blob/master/enr.md), including:
- **Relevant ENR Entries**:
  - `cgc`: Column Custody Group
  - Computed DataColumn indexes from the Custody Group
- **Node's Chain Status and Metadata (v3)**
- **Libp2p Information**:
  - UserAgent (typically Client + Version)
  - Supported protocols
  - Protocol version
  - Latency* (RTT for Ethereum's Ping RPC)
  - Peer ID and MultiAddrs
- **Summary table** of reported custody

## Features

The tool supports two operation modes:

### CLI Mode (Original)
Single node scanning with command-line interface and terminal output.

### Web UI Mode (New)
Web-based interface that allows:
- Configuring one API endpoint for multiple node scans
- Adding multiple ENR keys for parallel scanning
- Real-time results display with detailed information for each node
- Modern, responsive web interface

## Supported Networks

This experimental version of the tool is compatible with existing PeerDAS devnets. It has been tested and confirmed to work with `peerdas-devnet-7`.

More details available at:
- EF's [devnet-7 dashboard](https://peerdas-devnet-7.ethpandaops.io/)

## PeerDAS Specifications

To function correctly, the tool adheres to the networking requirements outlined in the PeerDAS specifications:
- [P2P Interface Specs](https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/p2p-interface.md)
- [Data Availability Sampling (DAS) Core](https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/das-core.md)
- [Peer Sampling Specs](https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/peer-sampling.md)

## Requirements
- `Go >=1.24`
- (Recommended) [Just](https://github.com/casey/just)
- A Beacon API with debugging events enabled (the tool downloads the beacon-state from the node)
  - Example: use EthPandaOps' Beacon RPC endpoint listed in the [devnet details](https://peerdas-devnet-7.ethpandaops.io/)

## Installation

We provide a `Justfile` that simplifies installation and building. Use the following commands:
```bash
# To build the tool locally -> binary at ./build/das-guardian
$ just build

# To install the tool -> binary placed at $GOPATH/bin/das-guardian
$ just install
```

## Usage

The tool exposes a single CLI command with two operation modes:

### CLI Mode (Single Node)
Basic usage for scanning a single node:
```bash
$ das-guardian --help

NAME:
   das-guardian - An Ethereum DAS custody checker with CLI and Web UI modes

USAGE:
   das-guardian [global options]

GLOBAL OPTIONS:
   --node.key string              ENR entry of the node we want to probe
   --libp2p.host string           IP for the Libp2p host (default: "127.0.0.1")
   --libp2p.port int              Port for the Libp2p host (default: 9013)
   --api.endpoint string          URL of a Beacon API (default: "http://127.0.0.1:5052/")
   --connection.retries int       Number of connection retries (default: 3)
   --connection.timeout duration  Connection timeout duration (default: 30s)
   --web.port int                 Port for the web server (default: 8080)
   --web.mode                     Enable web server mode (default: false)
   --help, -h                     Show help
```

Example of CLI mode usage:
```bash
$ das-guardian \
  --api.endpoint "https://beacon.fusaka-devnet-0.ethpandaops.io/" \
  --node.key "enr:-Oi4QJpqAuqmnU4iwQLrmyhIt62wrUeexYrTeXsCm06PWLnfPDK99h5mBt4IRmiLzvASKWjw74wsZV9UkzoPVggZj7kah2F0dG5ldHOIAAAAAAAAYACDY2djBIZjbGllbnTXiEdyYW5kaW5ljTEuMS4wLWExNTgwMjeEZXRoMpCDR4TGcFUmR4oCAAAAAAAAgmlkgnY0gmlwhM69sO-EcXVpY4IjKYlzZWNwMjU2azGhAoh6xQUKUjNR3_OtxCO9eOUAfxhTofTAbSFYLfr6a5pWiHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo"
```

### Web UI Mode
Start the web server:
```bash
$ das-guardian --web.mode --web.port 8080
```

Then open your browser to `http://localhost:8080` and:
1. Enter the Beacon API endpoint (e.g., `https://beacon.fusaka-devnet-0.ethpandaops.io/`)
2. Add multiple ENR keys (one per line)
3. Click "Scan Nodes" to process all nodes in parallel
4. View detailed results for each node including:
   - Peer information and custody groups
   - Libp2p connection details
   - Beacon status and metadata
   - Data availability sampling results in a table format

The web interface provides the same detailed information as the CLI mode but allows you to process multiple nodes simultaneously with a user-friendly interface.

Note: This tool is a demonstration prototype for debugging CL nodes on devnets. The codebase is experimental — please be gentle regarding its current style and implementation.

## Maintainers

[@cortze](https://github.com/cortze) from [@probe-lab](https://github.com/probe-lab)

## Contributing

Due to the debugging and research nature of the project, feedback and feature suggestions are very welcome. Feel free to open an issue or submit a pull request.
