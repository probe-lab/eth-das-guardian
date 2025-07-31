package api

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	devnetBeaconAPI = "https://beacon.fusaka-devnet-3.ethpandaops.io/"
	StateTimeout    = 30 * time.Second
	QueryTimeout    = 10 * time.Second
)

// API connection
func TestApiClient(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	err := httpCli.CheckConnection(testMainCtx)
	require.NoError(t, err)
}

// API endpoints
func TestApiClient_GetNodeVersion(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetNodeVersion(testMainCtx)
	require.NoError(t, err)
}

func TestApiClient_GetPeerDASstate(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetBeaconStateHead(testMainCtx)
	require.NoError(t, err)
}

func TestApiClient_GetForkChoice(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetForkChoice(testMainCtx)
	require.NoError(t, err)
}

func TestApiClient_TestBeaconBlock(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	// get the head of the chain
	bblock, err := httpCli.GetBeaconBlock(testMainCtx, "head")
	require.NoError(t, err)
	slot, err := bblock.Slot()
	require.NoError(t, err)

	// test that we get a propper error if we request a block that
	// is empty or doesn't exist
	_, err = httpCli.GetBeaconBlock(testMainCtx, slot+10)
	require.Error(t, ErrBlockNotFound, err)

	// test a failing
	_, err = httpCli.GetBeaconBlock(testMainCtx, 2*time.Second)
	require.Error(t, err)
}

func TestApiClient_GetNetworkConfig(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetNetworkConfig(testMainCtx)
	require.NoError(t, err)
}

func TestApiClient_GetNodeIdentity(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetNodeIdentity(testMainCtx)
	require.NoError(t, err)
}

func TestApiClient_GetConfigSpec(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetConfigSpecs(testMainCtx)
	require.NoError(t, err)
}

// generics
func genTestAPICli(t *testing.T) (*Client, context.Context, context.CancelFunc) {
	testMainCtx, cancel := context.WithCancel(context.Background())

	cfg := ClientConfig{
		Endpoint:     devnetBeaconAPI,
		StateTimeout: StateTimeout,
		QueryTimeout: QueryTimeout,
		Logger:       log.New(),
	}

	httpCli, err := NewClient(cfg)
	require.NoError(t, err)
	return httpCli, testMainCtx, cancel
}
