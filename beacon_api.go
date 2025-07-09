package dasguardian

import (
	"context"
	"fmt"
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
	GetForkDigest() ([]byte, error)
	GetFinalizedCheckpoint() *phase0.Checkpoint
	GetLatestBlockHeader() *phase0.BeaconBlockHeader
	GetFuluForkEpoch() int
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

	headState     *api.PeerDASstate
	forkSchedules api.ForkSchedule
	fuluForkEpoch int
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

	// get the network configuration from the apiCli
	forkSchedules, err := b.apiCli.GetNetworkConfig(ctx)
	if err != nil {
		return err
	}
	b.forkSchedules = forkSchedules.Data[FuluForkScheduleIdx] // we only need the fulu specifics

	// compose and get the local Metadata
	currentState, err := b.apiCli.GetPeerDASstate(ctx)
	if err != nil {
		return err
	}

	fuluForkEpoch, err := strconv.Atoi(b.forkSchedules.Epoch)
	if err != nil {
		return err
	}

	b.fuluForkEpoch = fuluForkEpoch

	if (int(currentState.Data.Slot) / 32) < fuluForkEpoch {
		secondsToFulu := time.Duration(((fuluForkEpoch*32)-int(currentState.Data.Slot))*12) * time.Second
		b.cfg.Logger.Warnf("network doesn't support fulu yet")
		b.cfg.Logger.Warnf("current: (slot: %d epoch: %d - version: %s)", currentState.Data.Slot, (currentState.Data.Slot / 32), currentState.Version)
		b.cfg.Logger.Warnf("target:  (slot: %d epoch: %d - missing: %d = %s)", fuluForkEpoch*32, fuluForkEpoch, (fuluForkEpoch*32)-int(currentState.Data.Slot), secondsToFulu)
		if b.cfg.WaitForFulu {
			b.cfg.Logger.Info("waiting for ", secondsToFulu)
			if secondsToFulu < 0 {
				return fmt.Errorf("neg time to fulu?!")
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
		} else {
			return fmt.Errorf("network doesn't support fulu yet (slot: %d - %s)", currentState.Data.Slot, currentState.Version)
		}
	} else {
		b.cfg.Logger.Info("fulu is supported")
		fmt.Sprintln((int(currentState.Data.Slot) / 32), fuluForkEpoch)
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

func (b *BeaconAPIImpl) GetForkDigest() ([]byte, error) {
	forkDigest, err := computeForkDigest(
		b.headState.Data.Fork.CurrentVersion[:],
		b.headState.Data.GenesisValidatorsRoot[:],
	)
	return forkDigest, err
}

func (b *BeaconAPIImpl) GetFinalizedCheckpoint() *phase0.Checkpoint {
	return b.headState.Data.FinalizedCheckpoint
}

func (b *BeaconAPIImpl) GetLatestBlockHeader() *phase0.BeaconBlockHeader {
	return b.headState.Data.LatestBlockHeader
}

func (b *BeaconAPIImpl) GetFuluForkEpoch() int {
	return b.fuluForkEpoch
}

func (b *BeaconAPIImpl) GetNodeIdentity(ctx context.Context) (*api.NodeIdentity, error) {
	return b.apiCli.GetNodeIdentity(ctx)
}

func (b *BeaconAPIImpl) GetBeaconBlock(ctx context.Context, slot uint64) (*spec.VersionedSignedBeaconBlock, error) {
	return b.apiCli.GetBeaconBlock(ctx, slot)
}
