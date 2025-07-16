package dasguardian

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/probe-lab/eth-das-guardian/api"
	log "github.com/sirupsen/logrus"
)

const (
	ApiStateTimeout     = 30 * time.Second
	ApiQueryTimeout     = 10 * time.Second
	FuluSupportRetry    = 12 * time.Second // 1 slot
	FuluForkScheduleIdx = 6                //  Fulu is the 7th fork -> index = 6
)

type BeaconAPI interface {
	Init(ctx context.Context) error
	GetStateVersion() string
	GetForkDigest(slot uint64) ([]byte, error)
	GetFinalizedCheckpoint() *phase0.Checkpoint
	GetLatestBlockHeader() *phase0.BeaconBlockHeader
	GetFuluForkEpoch() uint64
	GetNodeIdentity(ctx context.Context) (*api.NodeIdentity, error)
	GetBeaconBlock(ctx context.Context, slot uint64) (*spec.VersionedSignedBeaconBlock, error)
}

type BeaconAPIConfig struct {
	Logger      log.FieldLogger
	Endpoint    string
	WaitForFulu bool
}

type BeaconAPIImpl struct {
	cfg    BeaconAPIConfig
	apiCli *api.Client

	specs         map[string]any
	headState     *api.PeerDASstate
	forkSchedules api.ForkSchedule
	fuluForkEpoch uint64
}

func NewBeaconAPI(cfg BeaconAPIConfig) (BeaconAPI, error) {
	ethApiCfg := api.ClientConfig{
		Endpoint:     cfg.Endpoint,
		StateTimeout: ApiStateTimeout,
		QueryTimeout: ApiQueryTimeout,
	}
	apiCli, err := api.NewClient(ethApiCfg)
	if err != nil {
		return nil, err
	}

	return &BeaconAPIImpl{
		cfg:    cfg,
		apiCli: apiCli,
	}, nil
}

func (b *BeaconAPIImpl) Init(ctx context.Context) error {
	// check api connection
	if err := b.apiCli.CheckConnection(ctx); err != nil {
		return fmt.Errorf("connection to %s was stablished, but not active - %s", b.cfg.Endpoint, err.Error())
	}
	b.cfg.Logger.Info("connected to the beacon API...")

	// get the config specs from the apiCli
	specs, err := b.apiCli.GetConfigSpecs(ctx)
	if err != nil {
		return err
	}
	b.specs = specs

	// get the network configuration from the apiCli
	forkSchedules, err := b.apiCli.GetNetworkConfig(ctx)
	if err != nil {
		return err
	}

	if len(forkSchedules.Data) > FuluForkScheduleIdx {
		b.forkSchedules = forkSchedules.Data[FuluForkScheduleIdx] // we only need the fulu specifics
	}

	// compose and get the local Metadata
	currentState, err := b.apiCli.GetPeerDASstate(ctx)
	if err != nil {
		return err
	}

	var fuluForkEpoch uint64

	if len(forkSchedules.Data) > FuluForkScheduleIdx {
		fuluForkEpoch, err = strconv.ParseUint(b.forkSchedules.Epoch, 10, 64)
		if err != nil {
			return err
		}
	} else {
		fuluForkEpoch = math.MaxInt
	}

	b.fuluForkEpoch = fuluForkEpoch

	// Get timing configuration from beacon API specs
	// SECONDS_PER_SLOT is parsed as time.Duration by the config parser
	secondsPerSlotDuration, ok := b.specs["SECONDS_PER_SLOT"].(time.Duration)
	if !ok {
		return fmt.Errorf("SECONDS_PER_SLOT not found in beacon API config specs")
	}
	secondsPerSlot := uint64(secondsPerSlotDuration.Seconds())
	slotsPerEpoch, ok := b.specs["SLOTS_PER_EPOCH"].(uint64)
	if !ok {
		return fmt.Errorf("SLOTS_PER_EPOCH not found in beacon API config specs")
	}

	if (uint64(currentState.Data.Slot)/slotsPerEpoch) < fuluForkEpoch && fuluForkEpoch != math.MaxInt {
		secondsToFulu := time.Duration(((fuluForkEpoch*slotsPerEpoch)-uint64(currentState.Data.Slot))*secondsPerSlot) * time.Second
		b.cfg.Logger.Warnf("network doesn't support fulu yet")
		b.cfg.Logger.Warnf("current: (slot: %d epoch: %d - version: %s)", currentState.Data.Slot, (uint64(currentState.Data.Slot) / slotsPerEpoch), currentState.Version)
		b.cfg.Logger.Warnf("target:  (slot: %d epoch: %d - missing: %d slots = %s)", fuluForkEpoch*slotsPerEpoch, fuluForkEpoch, (fuluForkEpoch*slotsPerEpoch)-uint64(currentState.Data.Slot), secondsToFulu)
		b.cfg.Logger.Infof("timing config: %d seconds per slot, %d slots per epoch (fetched from beacon API)", secondsPerSlot, slotsPerEpoch)

		if b.cfg.WaitForFulu {
			b.cfg.Logger.Info("waiting for ", secondsToFulu)
			if secondsToFulu < 0 {
				return fmt.Errorf("negative time to fulu")
			}
			select {
			case <-ctx.Done():
				return fmt.Errorf("tooled closed without reaching fulu upgrade")

			case <-time.After(secondsToFulu):
				currentState, err = b.apiCli.GetPeerDASstate(ctx)
				if err != nil {
					return err
				}
			}
		}
	} else {
		b.cfg.Logger.Info("fulu is supported")
	}

	prettyLogrusFields(b.cfg.Logger, "dowloaded beacon head-state", map[string]any{
		"version":       currentState.Version,
		"finalized":     currentState.Finalized,
		"optimistic-el": currentState.ExecutionOptimistic,
		"validators":    len(currentState.Data.Validators),
	})

	b.headState = &currentState
	return nil
}

func (b *BeaconAPIImpl) GetStateVersion() string {
	return b.headState.Version
}

type BlobScheduleEntry struct {
	Epoch            uint64
	MaxBlobsPerBlock uint64
}

func (b *BeaconAPIImpl) GetForkDigest(slot uint64) ([]byte, error) {
	slotsPerEpoch, ok := b.specs["SLOTS_PER_EPOCH"].(uint64)
	if !ok {
		slotsPerEpoch = 32
	}

	currentEpoch := slot / slotsPerEpoch

	var forkVersion phase0.Version
	var isFuluActive bool
	var currentBlobParams *BlobScheduleEntry

	if forkEpoch, ok := b.specs["FULU_FORK_EPOCH"].(uint64); ok && currentEpoch >= forkEpoch {
		forkVersion = b.specs["FULU_FORK_VERSION"].(phase0.Version)
		isFuluActive = true
	} else if forkEpoch, ok := b.specs["ELECTRA_FORK_EPOCH"].(uint64); ok && currentEpoch >= forkEpoch {
		forkVersion = b.specs["ELECTRA_FORK_VERSION"].(phase0.Version)
	} else if forkEpoch, ok := b.specs["DENEB_FORK_EPOCH"].(uint64); ok && currentEpoch >= forkEpoch {
		forkVersion = b.specs["DENEB_FORK_VERSION"].(phase0.Version)
	} else if forkEpoch, ok := b.specs["CAPELLA_FORK_EPOCH"].(uint64); ok && currentEpoch >= forkEpoch {
		forkVersion = b.specs["CAPELLA_FORK_VERSION"].(phase0.Version)
	} else if forkEpoch, ok := b.specs["BELLATRIX_FORK_EPOCH"].(uint64); ok && currentEpoch >= forkEpoch {
		forkVersion = b.specs["BELLATRIX_FORK_VERSION"].(phase0.Version)
	} else if forkEpoch, ok := b.specs["ALTAIR_FORK_EPOCH"].(uint64); ok && currentEpoch >= forkEpoch {
		forkVersion = b.specs["ALTAIR_FORK_VERSION"].(phase0.Version)
	} else {
		forkVersion = b.specs["GENESIS_FORK_VERSION"].(phase0.Version)
	}

	if isFuluActive {
		maxBlobsPerBlockElectra, ok := b.specs["MAX_BLOBS_PER_BLOCK_ELECTRA"].(uint64)
		if !ok {
			maxBlobsPerBlockElectra = 0
		}

		currentBlobParams = &BlobScheduleEntry{
			Epoch:            b.specs["ELECTRA_FORK_EPOCH"].(uint64),
			MaxBlobsPerBlock: maxBlobsPerBlockElectra,
		}

		blobSchedule, ok := b.specs["BLOB_SCHEDULE"].([]any)
		if !ok {
			// BLOB_SCHEDULE is not present - this happens when no BPO (Blob Parameter Override) is scheduled
			b.cfg.Logger.Info("BLOB_SCHEDULE not found (no BPO scheduled), skipping blob parameter computation")
		}

		for _, blobScheduleEntry := range blobSchedule {
			blobScheduleMap := blobScheduleEntry.(map[string]any)
			epoch, ok := blobScheduleMap["EPOCH"].(uint64)
			if !ok {
				continue
			}

			if epoch <= currentEpoch {
				currentBlobParams.Epoch = epoch
				currentBlobParams.MaxBlobsPerBlock = blobScheduleMap["MAX_BLOBS_PER_BLOCK"].(uint64)
			} else {
				break
			}
		}
	}

	forkDigest := b.ComputeForkDigest(b.headState.Data.GenesisValidatorsRoot, forkVersion, currentBlobParams)
	return forkDigest[:], nil
}

func (b *BeaconAPIImpl) ComputeForkDigest(genesisValidatorsRoot phase0.Root, forkVersion phase0.Version, blobParams *BlobScheduleEntry) phase0.ForkDigest {
	forkData := phase0.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
	}

	forkDataRoot, _ := forkData.HashTreeRoot()

	// For Fulu fork and later, modify the fork digest with blob parameters
	if blobParams != nil {
		// serialize epoch and max_blobs_per_block as uint64 little-endian
		epochBytes := make([]byte, 8)
		maxBlobsBytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			epochBytes[i] = byte((blobParams.Epoch >> (8 * i)) & 0xff)
			maxBlobsBytes[i] = byte((blobParams.MaxBlobsPerBlock >> (8 * i)) & 0xff)
		}
		blobParamBytes := append(epochBytes, maxBlobsBytes...)

		blobParamHash := [32]byte{}
		{
			h := sha256.New()
			h.Write(blobParamBytes)
			copy(blobParamHash[:], h.Sum(nil))
		}

		// xor baseDigest with first 4 bytes of blobParamHash
		forkDigest := make([]byte, 4)
		for i := 0; i < 4; i++ {
			forkDigest[i] = forkDataRoot[i] ^ blobParamHash[i]
		}

		return phase0.ForkDigest(forkDigest)
	}

	return phase0.ForkDigest(forkDataRoot[:4])
}

func (b *BeaconAPIImpl) GetFinalizedCheckpoint() *phase0.Checkpoint {
	return b.headState.Data.FinalizedCheckpoint
}

func (b *BeaconAPIImpl) GetLatestBlockHeader() *phase0.BeaconBlockHeader {
	return b.headState.Data.LatestBlockHeader
}

func (b *BeaconAPIImpl) GetFuluForkEpoch() uint64 {
	return b.fuluForkEpoch
}

func (b *BeaconAPIImpl) GetNodeIdentity(ctx context.Context) (*api.NodeIdentity, error) {
	return b.apiCli.GetNodeIdentity(ctx)
}

func (b *BeaconAPIImpl) GetBeaconBlock(ctx context.Context, slot uint64) (*spec.VersionedSignedBeaconBlock, error) {
	return b.apiCli.GetBeaconBlock(ctx, slot)
}
