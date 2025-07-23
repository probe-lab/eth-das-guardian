package api

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/pkg/errors"
)

var (
	BlockBase        = "eth/v2/beacon/blocks/"
	ErrBlockNotFound = fmt.Errorf("block not found")
)

type BeaconBlock struct {
	Version             string                     `json:"version"`
	ExecutionOptimistic bool                       `json:"execution_optimistic"`
	Finalized           bool                       `json:"finalized"`
	Data                *electra.SignedBeaconBlock `json:"data"`
}

func (b *BeaconBlock) IsMissed() bool {
	return b.Data == nil
}

type FuluBeaconBlock struct {
	Slot          string                  `json:"slot"`
	ProposerIndex string                  `json:"proposer_index"`
	ParentRoot    string                  `json:"parent_root"`
	StateRoot     string                  `json:"state_root"`
	Body          electra.BeaconBlockBody `json:"body"`
}

func (c *Client) GetBeaconBlock(ctx context.Context, slot any) (*spec.VersionedSignedBeaconBlock, error) {
	// we only accept integers and strings to describe the slots
	blockQuery := BlockBase
	switch s := slot.(type) {
	case int, int32, int64, uint, uint32, uint64:
		blockQuery = blockQuery + fmt.Sprintf("%d", s)
	case string:
		blockQuery = s
	default:
		return nil, fmt.Errorf("unrecognized slot %s", slot)
	}

	versionedBlock := &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionElectra,
	}
	beaconBlock := &BeaconBlock{}
	resp, err := c.get(ctx, c.cfg.QueryTimeout, blockQuery, "")
	if err != nil {
		if strings.Contains(err.Error(), "404 Not Found") {
			return new(spec.VersionedSignedBeaconBlock), ErrBlockNotFound
		}
		return nil, errors.Wrap(err, "requesting beacon-block")
	}
	err = json.Unmarshal(resp, &beaconBlock)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling beacon-block from http request")
	}

	versionedBlock.Electra = beaconBlock.Data
	return versionedBlock, nil
}
