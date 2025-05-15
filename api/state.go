package api

import (
	"context"
	"encoding/json"

	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/pkg/errors"
)

var (
	BeaconStateBase = "eth/v2/debug/beacon/states/head"
)

type PeerDASstate struct {
	Version             string              `json:"version"`
	ExecutionOptimistic bool                `json:"execution_optimistic"`
	Finalized           bool                `json:"finalized"`
	Data                electra.BeaconState `json:"data"`
}

func (c *Client) GetPeerDASstate(ctx context.Context) (PeerDASstate, error) {
	var state PeerDASstate

	resp, err := c.get(ctx, c.cfg.QueryTimeout, BeaconStateBase, "")
	if err != nil {
		return state, errors.Wrap(err, "requesting beacon-state")
	}

	err = json.Unmarshal(resp, &state)
	if err != nil {
		return state, errors.Wrap(err, "unmarshaling beacon-state from http request")
	}

	return state, nil
}
