package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/pkg/errors"
)

var BlockBase = "eth/v2/beacon/blocks/%d"

type BeaconBlock struct {
	Version             string                     `json:"version"`
	ExecutionOptimistic bool                       `json:"execution_optimistic"`
	Finalized           bool                       `json:"finalized"`
	Data                *electra.SignedBeaconBlock `json:"data"`
}

type FuluBeaconBlock struct {
	Slot          string                  `json:"slot"`
	ProposerIndex string                  `json:"proposer_index"`
	ParentRoot    string                  `json:"parent_root"`
	StateRoot     string                  `json:"state_root"`
	Body          electra.BeaconBlockBody `json:"body"`
}

func (c *Client) GetBeaconBlock(ctx context.Context, slot uint64) (*spec.VersionedSignedBeaconBlock, error) {
	versionedBlock := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionElectra,
	}
	beaconBlock := &BeaconBlock{}
	resp, err := c.get(ctx, c.cfg.QueryTimeout, fmt.Sprintf(BlockBase, slot), "")
	if err != nil {
		return nil, errors.Wrap(err, "requesting beacon-block")
	}
	err = json.Unmarshal(resp, &beaconBlock)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling beacon-block from http request")
	}

	versionedBlock.Electra = beaconBlock.Data
	return versionedBlock, nil
}
