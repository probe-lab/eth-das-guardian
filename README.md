# Eth DAS Guardian

The `eth-das-guardian` tool presented in this repo is an experimental, semi-standalone utility for assessing data-column custody in the [PeerDAS](https://eips.ethereum.org/EIPS/eip-7594) context. It logs and debugs all relevant information related to connecting to a remote node and verifying whether it retains and shares the data columns it claims custody of.

It can extract and present all available information for a given [ENR](https://github.com/ethereum/devp2p/blob/master/enr.md), including:
- **Relevant ENR Entries**:
  - `cgc`: Column Custody Group
  - Computed DataColumn indexes from the Custody Group
- **Node's Chain Status (v1-v2) and Metadata (v2-v3)**
- **Libp2p Information**:
  - UserAgent (typically Client + Version)
  - Supported protocols
  - Protocol version
  - Latency* (RTT for Ethereum's Ping RPC)
  - Peer ID and MultiAddrs
- **Summary table** of reported custody

## Supported Networks

This experimental version of the tool is compatible with existing PeerDAS devnets. It has been tested and confirmed to work with `fusaka-devnet-2`.

More details available at:
- EF's [fusaka-devnet-3 dashboard](https://fusaka-devnet-3.ethpandaops.io/)

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
   das-guardian - An ethereum DAS custody checker

USAGE:
   das-guardian [global options] [command [command options]]

COMMANDS:
   scan     Connects and scans a given node for its custody and network status
   monitor  Connects and monitors a given node for its custody and network status
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --libp2p.host string           IP for the Libp2p host (default: "127.0.0.1")
   --libp2p.port int              Port for the libp2p host (default: 9013)
   --api.endpoint string          The url endpoint of a Beacon API (http://localhost:5052/) (default: "http://127.0.0.1:5052/")
   --api.custom.cl string         Name of a custom CL client that we would like to query from the work-balancer ('lighthouse', 'prysm', 'nimbus')
   --connection.retries int       Number of retries when connecting the node (default: 3)
   --connection.timeout duration  Timeout for the connection attempt to the node (default: 30s)
   --init.timeout duration        Timeout to limit the time it can take the guardian to init itself (default: 30s)
   --wait.fulu                    The guardian command will wait until fulu hardfork has happened before proceeding to test the custody (default: true)
   --help, -h                     show help
```

Example of how to use it:
```bash
$ das-guardian --api.endpoint "https://beacon.fusaka-devnet-2.ethpandaops.io/" --api.custom.cl "lighthouse" scan --scan.key "enr:-PO4QFAZca5TDfbiiCKouERBRao_oLgy5KCPvbezPfhTacxHWlBqfDgsfsghRLBUH9W8bj08v1jkd64UoUjSaWZx-6UHh2F0dG5ldHOIAAAAAAADAACDY2djgYCGY2xpZW502IpMaWdodGhvdXNljDcuMS4wLWJldGEuMIRldGgykIEAExpwk3VEAAEAAAAAAACCaWSCdjSCaXCEn99xd4NuZmSENp-J94RxdWljgiMpiXNlY3AyNTZrMaEDzVa77_o452OzzqylcK2mA0DREidLotbGonvz3nogDS-Ic3luY25ldHMPg3RjcIIjKIN1ZHCCIyg"
INFO[0000] running das-guardian                          beacon-api="https://beacon.fusaka-devnet-2.ethpandaops.io/" beacon-cl-client=lighthouse connection-retries=3 connection-timeout=30s init-timeout=30s libp2p-host=127.0.0.1 libp2p-port=9013 slot-range-number=5 slot-range-slots="[]" slot-range-type=random wait-fulu=true
INFO[0001] successfull connection to the beacon-api      node-version=Lighthouse/v7.1.0-beta.0-9993fdf/x86_64-linux
INFO[0001] connected to the beacon API...
INFO[0001] Beacon node identity                          enr="enr:-O24QMLrZGfQAo8_Svw5lG83kn6XTfiUmMP9Zz6yFayAX1sLNKjAegt04iXwWxVsclGtz0E1Ec77mTe6xT0zlJKdgn2BmIdhdHRuZXRziAAABgAAAAAAg2NnY4GAhmNsaWVudNGKTGlnaHRob3VzZYU3LjEuMIRldGgykLYvKw5wk3VE__________-CaWSCdjSCaXCEpFrLSoNuZmSEti8rDoRxdWljgiMpiXNlY3AyNTZrMaEC-HAEr6PikSNtSPQj7LoDBjzA4lRhjKXzLZMkfPa6c1CIc3luY25ldHMNg3RjcIIjKIN1ZHCCIyg" peer_id=16Uiu2HAmC9UA9nyCov1VAaWPSjycJPLjSLd49SEQWzFpp4EBSa4P
INFO[0005] fulu is supported
INFO[0005] dowloaded beacon head-state
INFO[0005] 	* version:	fulu
INFO[0005] 	* finalized:	false
INFO[0005] 	* optimistic-el:	false
INFO[0005] 	* validators:	736
INFO[0005] local beacon-status
INFO[0005] 	* head-slot:	152900
INFO[0005] 	* fork-digest:	0xb62f2b0e
INFO[0005] local beacon-metadata
INFO[0005] 	* syncnets:	[0]
INFO[0005] 	* seq-number:	0
INFO[0005] 	* attnets:	[0 0 0 0 0 0 0 0]
INFO[0005] das-guardian initialized                      peer-id=16Uiu2HAmVMkBPZgCq4oqzEvTBrfkPwwHK3K8HKixCsheKeRFtEAH
INFO[0006] connected to remote node...
INFO[0006] libp2p info...
INFO[0006] 	* ping_rtt:	105.853822ms
...
INFO[0013] sampling node for...                          columns=128 slots=5
INFO[0014] req info...                                   das-result="128/128 columns" req-duration=1.063251291s slot=99067
INFO[0015] req info...                                   das-result="0/128 columns" req-duration=537.631558ms slot=78000
INFO[0015] req info...                                   das-result="128/128 columns" req-duration=435.80515ms slot=147141
INFO[0016] req info...                                   das-result="0/128 columns" req-duration=189.822971ms slot=107529
INFO[0016] req info...                                   das-result="128/128 columns" req-duration=130.425776ms slot=33121
INFO[0016] node custody sampling done...                 duration=2.35818963s
```

Note: This tool is a demonstration prototype for debugging CL nodes on devnets. The codebase is experimental — please be gentle regarding its current style and implementation.

## Maintainers
[@cortze](https://github.com/cortze) from [@probe-lab](https://github.com/probe-lab)
[@EthPandaOps](https://github.com/ethpandaops) team

## Contributing
Due to the debugging and research nature of the project, feedback and feature suggestions are very welcome. Feel free to open an issue or submit a pull request.
