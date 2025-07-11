package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/pkg/errors"
)

var GenesisBase = "eth/v1/beacon/genesis"

type GenesisDataRaw struct {
	GenesisTime          string `json:"genesis_time"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
	GenesisForkVersion   string `json:"genesis_fork_version"`
}

type GenesisData struct {
	GenesisTime          string              `json:"genesis_time"`
	GenesisValidatorsRoot phase0.Root        `json:"genesis_validators_root"`
	GenesisForkVersion   phase0.Version     `json:"genesis_fork_version"`
}

type GenesisResponse struct {
	Data GenesisDataRaw `json:"data"`
}

func (c *Client) GetGenesis(ctx context.Context) (*GenesisData, error) {
	resp, err := c.get(ctx, c.cfg.QueryTimeout, GenesisBase, "")
	if err != nil {
		return nil, errors.Wrap(err, "requesting genesis")
	}

	var genesisResp GenesisResponse
	err = json.Unmarshal(resp, &genesisResp)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling genesis from http request")
	}

	// Parse genesis_validators_root
	gvrBytes, err := hex.DecodeString(strings.TrimPrefix(genesisResp.Data.GenesisValidatorsRoot, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "parsing genesis_validators_root")
	}
	var genesisValidatorsRoot phase0.Root
	copy(genesisValidatorsRoot[:], gvrBytes)

	// Parse genesis_fork_version
	gfvBytes, err := hex.DecodeString(strings.TrimPrefix(genesisResp.Data.GenesisForkVersion, "0x"))
	if err != nil {
		return nil, errors.Wrap(err, "parsing genesis_fork_version")
	}
	var genesisForkVersion phase0.Version
	copy(genesisForkVersion[:], gfvBytes)

	return &GenesisData{
		GenesisTime:          genesisResp.Data.GenesisTime,
		GenesisValidatorsRoot: genesisValidatorsRoot,
		GenesisForkVersion:   genesisForkVersion,
	}, nil
}