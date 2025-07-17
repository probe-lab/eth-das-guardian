package dasguardian

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
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

	// Get node identity and ENR
	nodeIdentity, err := b.apiCli.GetNodeIdentity(ctx)
	if err != nil {
		b.cfg.Logger.WithError(err).Warn("failed to get node identity")
	} else {
		b.cfg.Logger.WithFields(log.Fields{
			"peer_id": nodeIdentity.Data.PeerID,
			"enr":     nodeIdentity.Data.Enr,
		}).Info("Beacon node identity")

		if len(nodeIdentity.Data.Maddrs) > 0 {
			b.cfg.Logger.WithFields(log.Fields{
				"p2p_addresses": nodeIdentity.Data.Maddrs,
			}).Debug("Beacon node P2P addresses")
		}
	}

	// get the config specs from the apiCli
	specs, err := b.apiCli.GetConfigSpecs(ctx)
	if err != nil {
		return err
	}
	b.specs = specs

	// Get genesis data from the proper endpoint
	genesisData, err := b.apiCli.GetGenesis(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get genesis data")
	}

	// Add GENESIS_VALIDATORS_ROOT to specs from the genesis endpoint
	b.specs["GENESIS_VALIDATORS_ROOT"] = genesisData.GenesisValidatorsRoot

	// Debug: log what we got from beacon API specs
	if log.GetLevel() >= log.DebugLevel {
		b.cfg.Logger.WithFields(log.Fields{
			"specs_count":                 len(specs),
			"has_genesis_validators_root": specs["GENESIS_VALIDATORS_ROOT"] != nil,
			"genesis_validators_root":     fmt.Sprintf("0x%x", genesisData.GenesisValidatorsRoot),
		}).Debug("Beacon API specs and genesis data loaded")

		// Log a few important keys for debugging
		for _, key := range []string{"GENESIS_VALIDATORS_ROOT", "GENESIS_FORK_VERSION", "DENEB_FORK_EPOCH", "ELECTRA_FORK_EPOCH", "FULU_FORK_EPOCH"} {
			if val, exists := specs[key]; exists && val != nil {
				b.cfg.Logger.WithFields(log.Fields{
					"key":   key,
					"value": fmt.Sprintf("%v", val),
				}).Debug("Important spec value")
			} else {
				b.cfg.Logger.WithFields(log.Fields{
					"key":    key,
					"exists": exists,
					"is_nil": val == nil,
				}).Debug("Missing or nil spec value")
			}
		}
	}

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

	// Use genesis validators root from specs (fetched from genesis endpoint)
	genesisValidatorsRoot := b.specs["GENESIS_VALIDATORS_ROOT"].(phase0.Root)

	if log.GetLevel() >= log.DebugLevel {
		b.cfg.Logger.WithFields(log.Fields{
			"beacon_api_endpoint":     b.cfg.Endpoint,
			"slot":                    slot,
			"current_epoch":           currentEpoch,
			"genesis_validators_root": fmt.Sprintf("0x%x", genesisValidatorsRoot),
			"slots_per_epoch":         slotsPerEpoch,
		}).Debug("Beacon API network configuration")
	}

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

		if log.GetLevel() >= log.DebugLevel {
			b.cfg.Logger.WithFields(log.Fields{
				"electra_fork_epoch":          b.specs["ELECTRA_FORK_EPOCH"].(uint64),
				"max_blobs_per_block_electra": maxBlobsPerBlockElectra,
			}).Debug("Initial BPO parameters set for Fulu")
		}

		blobSchedule, ok := b.specs["BLOB_SCHEDULE"].([]any)
		if !ok {
			// BLOB_SCHEDULE is not present - this happens when no BPO (Blob Parameter Override) is scheduled.
			b.cfg.Logger.Warn("BLOB_SCHEDULE not found, if one is expected, this will cause this will cause network incompatibility")
		}

		type blobParam struct {
			Epoch            uint64
			MaxBlobsPerBlock uint64
		}

		var parsedSchedule []blobParam

		for _, blobScheduleEntry := range blobSchedule {
			blobScheduleMap := blobScheduleEntry.(map[string]any)
			epoch := blobScheduleMap["EPOCH"].(uint64)
			maxBlobs := blobScheduleMap["MAX_BLOBS_PER_BLOCK"].(uint64)

			parsedSchedule = append(parsedSchedule, blobParam{
				Epoch:            epoch,
				MaxBlobsPerBlock: maxBlobs,
			})
		}

		sort.Slice(parsedSchedule, func(i, j int) bool {
			return parsedSchedule[i].Epoch < parsedSchedule[j].Epoch
		})

		for _, param := range parsedSchedule {
			if param.Epoch <= currentEpoch {
				currentBlobParams.Epoch = param.Epoch
				currentBlobParams.MaxBlobsPerBlock = param.MaxBlobsPerBlock
			}
		}
	}

	forkDigest := b.ComputeForkDigest(genesisValidatorsRoot, forkVersion, currentBlobParams)

	if log.GetLevel() >= log.DebugLevel {
		b.cfg.Logger.WithFields(log.Fields{
			"detected_fork_version":   fmt.Sprintf("0x%x", forkVersion),
			"is_fulu_active":          isFuluActive,
			"final_fork_digest":       fmt.Sprintf("0x%x", forkDigest),
			"genesis_validators_root": fmt.Sprintf("0x%x", genesisValidatorsRoot),
			"current_epoch":           currentEpoch,
			"slot":                    slot,
			"blob_params_present":     currentBlobParams != nil,
		}).Debug("Fork digest calculation result")

		if currentBlobParams != nil {
			b.cfg.Logger.WithFields(log.Fields{
				"blob_params_epoch":     currentBlobParams.Epoch,
				"blob_params_max_blobs": currentBlobParams.MaxBlobsPerBlock,
			}).Debug("BPO blob parameters used in fork digest")
		}
	}

	return forkDigest[:], nil
}

func (b *BeaconAPIImpl) ComputeForkDigest(genesisValidatorsRoot phase0.Root, forkVersion phase0.Version, blobParams *BlobScheduleEntry) phase0.ForkDigest {
	forkData := phase0.ForkData{
		CurrentVersion:        forkVersion,
		GenesisValidatorsRoot: genesisValidatorsRoot,
	}

	forkDataRoot, _ := forkData.HashTreeRoot()
	baseForkDigest := forkDataRoot[:4]

	if log.GetLevel() >= log.DebugLevel {
		b.cfg.Logger.WithFields(log.Fields{
			"fork_version":            fmt.Sprintf("0x%x", forkVersion),
			"genesis_validators_root": fmt.Sprintf("0x%x", genesisValidatorsRoot),
			"fork_data_root":          fmt.Sprintf("0x%x", forkDataRoot),
			"base_fork_digest":        fmt.Sprintf("0x%x", baseForkDigest),
		}).Debug("Fork digest base calculation")
	}

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

		if log.GetLevel() >= log.DebugLevel {
			b.cfg.Logger.WithFields(log.Fields{
				"blob_param_bytes": fmt.Sprintf("0x%x", blobParamBytes),
				"blob_param_hash":  fmt.Sprintf("0x%x", blobParamHash),
				"bpo_fork_digest":  fmt.Sprintf("0x%x", forkDigest),
			}).Debug("BPO fork digest calculation")
		}

		return phase0.ForkDigest(forkDigest)
	}

	if log.GetLevel() >= log.DebugLevel {
		b.cfg.Logger.Debug("Using base fork digest (no BPO)")
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
