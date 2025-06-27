package api

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
)

var ConfigBase = "eth/v1/config/fork_schedule"

type NetworkConfig struct {
	Data []ForkSchedule `json:"data"`
}

type ForkSchedule struct {
	PreviousVersion string `json:"previous_version"`
	CurrentVersion  string `json:"current_version"`
	Epoch           string `json:"epoch"`
}

func (c *Client) GetNetworkConfig(ctx context.Context) (NetworkConfig, error) {
	var netConf NetworkConfig
	resp, err := c.get(ctx, c.cfg.QueryTimeout, ConfigBase, "")
	if err != nil {
		return netConf, errors.Wrap(err, "requesting fork-schedule")
	}
	err = json.Unmarshal(resp, &netConf)
	if err != nil {
		return netConf, errors.Wrap(err, "unmarshaling network-config from http request")
	}
	return netConf, nil
}
