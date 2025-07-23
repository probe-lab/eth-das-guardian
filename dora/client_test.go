package dora

import (
	"context"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

var (
	DoraTestAPIEndpoint = "https://dora.fusaka-devnet-2.ethpandaops.io/api/"
	StateTimeout        = 30 * time.Second
	QueryTimeout        = 10 * time.Second
)

// API connection
func TestDoraApiClient(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	err := httpCli.CheckConnection(testMainCtx)
	require.NoError(t, err)
}

// API endpoints
func TestDoraApiClient_GetEpoch(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetEpochV1(testMainCtx, "latest")
	require.NoError(t, err)
}

func TestDoraApiClient_GetNetworkConsensusNodes(t *testing.T) {
	httpCli, testMainCtx, cancel := genTestAPICli(t)
	defer cancel()

	_, err := httpCli.GetConsensusClients(testMainCtx)
	require.NoError(t, err)
}

// generics
func genTestAPICli(t *testing.T) (*Client, context.Context, context.CancelFunc) {
	testMainCtx, cancel := context.WithCancel(context.Background())

	cfg := ClientConfig{
		Endpoint:     DoraTestAPIEndpoint,
		StateTimeout: StateTimeout,
		QueryTimeout: QueryTimeout,
		Logger:       log.WithFields(log.Fields{}),
	}

	httpCli, err := NewClient(cfg)
	require.NoError(t, err)
	return httpCli, testMainCtx, cancel
}
