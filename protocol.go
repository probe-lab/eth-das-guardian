package dasguardian

import "github.com/attestantio/go-eth2-client/spec/phase0"

// Ethereum 2.0 P2P protocol IDs
const (
	RPCPingTopicV1                      = "/eth2/beacon_chain/req/ping/1/ssz_snappy"
	RPCGoodByeTopicV1                   = "/eth2/beacon_chain/req/goodbye/1/ssz_snappy"
	RPCStatusTopicV1                    = "/eth2/beacon_chain/req/status/1/ssz_snappy"
	RPCStatusTopicV2                    = "/eth2/beacon_chain/req/status/2/ssz_snappy"
	RPCMetaDataTopicV1                  = "/eth2/beacon_chain/req/metadata/1/ssz_snappy"
	RPCMetaDataTopicV2                  = "/eth2/beacon_chain/req/metadata/2/ssz_snappy"
	RPCMetaDataTopicV3                  = "/eth2/beacon_chain/req/metadata/3/ssz_snappy"
	RPCBlocksByRangeTopicV1             = "/eth2/beacon_chain/req/beacon_blocks_by_range/1/ssz_snappy"
	RPCBlocksByRangeTopicV2             = "/eth2/beacon_chain/req/beacon_blocks_by_range/2/ssz_snappy"
	RPCBlocksByRootTopicV1              = "/eth2/beacon_chain/req/beacon_blocks_by_root/1/ssz_snappy"
	RPCBlocksByRootTopicV2              = "/eth2/beacon_chain/req/beacon_blocks_by_root/2/ssz_snappy"
	RPCBlobSidecarsByRangeTopicV1       = "/eth2/beacon_chain/req/blob_sidecars_by_range/1/ssz_snappy"
	RPCBlobSidecarsByRootTopicV1        = "/eth2/beacon_chain/req/blob_sidecars_by_root/1/ssz_snappy"
	RPCDataColumnsByRangeV1             = "/eth2/beacon_chain/req/data_columns_by_range/1/ssz_snappy"
	RPCDataColumnsByRootV1              = "/eth2/beacon_chain/req/data_columns_by_root/1/ssz_snappy"
	RPCDataColumnSidecarsByRangeTopicV1 = "/eth2/beacon_chain/req/data_column_sidecars_by_range/1/ssz_snappy"
	RPCDataColumnSidecarsByRootTopicV1  = "/eth2/beacon_chain/req/data_column_sidecars_by_root/1/ssz_snappy"
)

// Request/Response message types for Ethereum 2.0 P2P protocols
type SSZUint64 uint64

// StatusV1 represents the beacon chain status
type StatusV1 struct {
	ForkDigest     [4]byte  `ssz-size:"4"`
	FinalizedRoot  [32]byte `ssz-size:"32"`
	FinalizedEpoch uint64
	HeadRoot       [32]byte `ssz-size:"32"`
	HeadSlot       uint64
}

// StatusV2 represents the beacon chain status
type StatusV2 struct {
	ForkDigest            [4]byte  `ssz-size:"4"`
	FinalizedRoot         [32]byte `ssz-size:"32"`
	FinalizedEpoch        uint64
	HeadRoot              [32]byte `ssz-size:"32"`
	HeadSlot              uint64
	EarliestAvailableSlot uint64
}

// MetaDataV1 represents the peer's metadata (Phase 0)
type MetaDataV1 struct {
	SeqNumber uint64
	Attnets   [8]byte `ssz-size:"8"` // Bitvector[ATTESTATION_SUBNET_COUNT]
}

// MetaDataV2 represents the peer's metadata (Altair+ with syncnets)
type MetaDataV2 struct {
	SeqNumber uint64
	Attnets   [8]byte `ssz-size:"8"` // Bitvector[ATTESTATION_SUBNET_COUNT]
	Syncnets  [1]byte `ssz-size:"1"` // Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]
}

// MetaDataV3 represents the peer's metadata (Fulu+ with custody_group_count for PeerDAS)
type MetaDataV3 struct {
	SeqNumber         uint64
	Attnets           [8]byte `ssz-size:"8"` // Bitvector[ATTESTATION_SUBNET_COUNT]
	Syncnets          [1]byte `ssz-size:"1"` // Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]
	CustodyGroupCount uint64  // custody_group_count (cgc)
}

type BeaconBlocksByRangeRequestV1 struct {
	StartSlot uint64
	Count     uint64
	Step      uint64
}

type DataColumnSidecarsByRangeRequestV1 struct {
	StartSlot uint64
	Count     uint64
	Columns   []uint64
}

type DataColumnSidecarV1 struct {
	Index                        uint64
	Column                       [][]byte `ssz-max:"4096" ssz-size:"?,2048"`
	KzgCommitments               [][]byte `ssz-max:"4096" ssz-size:"?,48"`
	KzgProofs                    [][]byte `ssz-max:"4096" ssz-size:"?,48"`
	SignedBlockHeader            *phase0.SignedBeaconBlockHeader
	KzgCommitmentsInclusionProof [][]byte `ssz-size:"4,32"`
}
