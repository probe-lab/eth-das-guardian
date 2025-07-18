package dasguardian

import (
	"context"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/probe-lab/eth-das-guardian/api"
	"github.com/stretchr/testify/mock"
)

// mockBeaconAPI satisfies the BeaconAPI interface
type mockBeaconAPI struct {
	mock.Mock
}

func (m *mockBeaconAPI) Init(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *mockBeaconAPI) GetStateVersion() string {
	args := m.Called()
	return args.String(0)
}

func (m *mockBeaconAPI) GetForkDigest(slot uint64) ([]byte, error) {
	args := m.Called(slot)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *mockBeaconAPI) GetFinalizedCheckpoint() *phase0.Checkpoint {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*phase0.Checkpoint)
}

func (m *mockBeaconAPI) GetLatestBlockHeader() *phase0.BeaconBlockHeader {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*phase0.BeaconBlockHeader)
}

func (m *mockBeaconAPI) GetFuluForkEpoch() uint64 {
	args := m.Called()
	return args.Get(0).(uint64)
}

func (m *mockBeaconAPI) GetNodeIdentity(ctx context.Context) (*api.NodeIdentity, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*api.NodeIdentity), args.Error(1)
}

func (m *mockBeaconAPI) GetBeaconBlock(ctx context.Context, slot uint64) (*spec.VersionedSignedBeaconBlock, error) {
	args := m.Called(ctx, slot)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*spec.VersionedSignedBeaconBlock), args.Error(1)
}

func (m *mockBeaconAPI) ReadSpecParameter(key string) (any, bool) {
	args := m.Called(key)
	return args.Get(0), args.Bool(1)
}
