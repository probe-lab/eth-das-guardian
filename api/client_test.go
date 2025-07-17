package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	localAvailTestIP = "https://beacon.berlinterop-devnet-2.ethpandaops.io/"
	StateTimeout     = 30 * time.Second
	QueryTimeout     = 10 * time.Second
)

// API connection
func Test_APIClient(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	err := httpCli.CheckConnection(testMainCtx)
	require.NoError(t, err)
}

// API endpoints
func Test_ApiGetNodeVersion(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetNodeVersion(testMainCtx)
	require.NoError(t, err)
}

func Test_ApiGetPeerDASstate(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetBeaconStateHead(testMainCtx)
	require.NoError(t, err)
}

func Test_ApiGetForkChoice(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetForkChoice(testMainCtx)
	require.NoError(t, err)
}

func Test_ApiGetNetworkConfig(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetNetworkConfig(testMainCtx)
	require.NoError(t, err)
}

func Test_ApiGetNodeIdentity(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetNodeIdentity(testMainCtx)
	require.NoError(t, err)
}

// generics
func genTestAPICli(t *testing.T) (*Client, context.Context, context.CancelFunc) {
	testMainCtx, cancel := context.WithCancel(context.Background())

	cfg := ClientConfig{
		Endpoint:     localAvailTestIP,
		StateTimeout: StateTimeout,
		QueryTimeout: QueryTimeout,
	}

	httpCli, err := NewClient(cfg)
	require.NoError(t, err)
	return httpCli, testMainCtx, cancel
}
