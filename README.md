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
  - Example: use EthPandaOps’ Beacon RPC endpoint listed in the [devnet details](https://peerdas-devnet-7.ethpandaops.io/)

## Installation

We provide a `Justfile` that simplifies installation and building. Use the following commands:
```bash
# To build the tool locally -> binary at ./build/das-guardian
$ just build

# To install the tool -> binary placed at $GOPATH/bin/das-guardian
$ just install
```

## Usage

The tool exposes a single CLI command. Basic usage:
```bash
$ das-guardian --help

NAME:
   das-guardian - An Ethereum DAS custody checker

USAGE:
   das-guardian [global options]

GLOBAL OPTIONS:
   --node.key string              ENR of the node to probe
   --libp2p.host string           IP address for the Libp2p host (default: "127.0.0.1")
   --libp2p.port int              Port for the Libp2p host (default: 9013)
   --api.endpoint string          URL of a Beacon API (default: "http://127.0.0.1:5052/")
   --connection.retries int       Number of connection retries (default: 3)
   --connection.timeout duration  Connection timeout duration (default: 30s)
   --help, -h                     Show help
```

Example of how to use it:
```bash
$ das-guardian \
  --api.endpoint "https://beacon.peerdas-devnet-7.ethpandaops.io/" \
  --node.key "enr:-Oi4QJpqAuqmnU4iwQLrmyhIt62wrUeexYrTeXsCm06PWLnfPDK99h5mBt4IRmiLzvASKWjw74wsZV9UkzoPVggZj7kah2F0dG5ldHOIAAAAAAAAYACDY2djBIZjbGllbnTXiEdyYW5kaW5ljTEuMS4wLWExNTgwMjeEZXRoMpCDR4TGcFUmR4oCAAAAAAAAgmlkgnY0gmlwhM69sO-EcXVpY4IjKYlzZWNwMjU2azGhAoh6xQUKUjNR3_OtxCO9eOUAfxhTofTAbSFYLfr6a5pWiHN5bmNuZXRzD4N0Y3CCIyiDdWRwgiMo"

INFO[0000] Running eth-das-guardian                      beacon-api="https://beacon.peerdas-devnet-7.ethpandaops.io/" connection-retries=3 connection-timeout=30s libp2p-host=127.0.0.1 libp2p-port=9013 node-key="enr:-Oi4QJ..."
INFO[0000] Successfully connected to the Beacon API      node-version=Lodestar/v1.28.1/1f339ea
INFO[0000] Connected to the Beacon API...
INFO[0002] Downloaded beacon head-state
INFO[0002]   * Validators:      336
INFO[0002]   * Version:         fulu
INFO[0002]   * Finalized:       false
INFO[0002]   * Optimistic EL:   false
...
INFO[0003] requesting slot-blocks from beacon API...     slots="[113791 99432 73995 66414]"
INFO[0005] sampling node for...                          columns=4 slots=4
INFO[0005] req info...                                   das-result="4/4 columns" req-duration=231.7413ms slot=113791
INFO[0005] req info...                                   das-result="4/4 columns" req-duration=121.785912ms slot=99432
INFO[0005] req info...                                   das-result="4/4 columns" req-duration=118.819413ms slot=73995
INFO[0005] req info...                                   das-result="4/4 columns" req-duration=119.066869ms slot=66414
INFO[0005] node custody sampling done...                 duration=592.556056ms
┌────────┬────────────────────────────────┬────────────────────────────────┬────────────────────────────────┬────────────────────────────────┐
│  SLOT  │          COL  [ 28 ]           │          COL  [ 32 ]           │          COL  [ 57 ]           │          COL  [ 117 ]          │
├────────┼────────────────────────────────┼────────────────────────────────┼────────────────────────────────┼────────────────────────────────┤
│ 113791 │ blobs (5/5) / kzg-cmts (5/5/5) │ blobs (5/5) / kzg-cmts (5/5/5) │ blobs (5/5) / kzg-cmts (5/5/5) │ blobs (5/5) / kzg-cmts (5/5/5) │
│ 99432  │ blobs (7/7) / kzg-cmts (7/7/7) │ blobs (7/7) / kzg-cmts (7/7/7) │ blobs (7/7) / kzg-cmts (7/7/7) │ blobs (7/7) / kzg-cmts (7/7/7) │
│ 73995  │ blobs (5/5) / kzg-cmts (5/5/5) │ blobs (5/5) / kzg-cmts (5/5/5) │ blobs (5/5) / kzg-cmts (5/5/5) │ blobs (5/5) / kzg-cmts (5/5/5) │
│ 66414  │ blobs (4/4) / kzg-cmts (4/4/4) │ blobs (4/4) / kzg-cmts (4/4/4) │ blobs (4/4) / kzg-cmts (4/4/4) │ blobs (4/4) / kzg-cmts (4/4/4) │
└────────┴────────────────────────────────┴────────────────────────────────┴────────────────────────────────┴────────────────────────────────┘
```

Note: This tool is a demonstration prototype for debugging CL nodes on devnets. The codebase is experimental — please be gentle regarding its current style and implementation.

## TODOs:
- [ ] structure code on right packages
- [ ] make interface to evaluate the results
- [ ] make logic to limit requested slots for fulu-only slots
- [ ] add nebula logic
- [ ] 

## Maintainers

[@cortze](https://github.com/cortze) from [@probe-lab](https://github.com/probe-lab)

## Contributing

Due to the debugging and research nature of the project, feedback and feature suggestions are very welcome. Feel free to open an issue or submit a pull request.
