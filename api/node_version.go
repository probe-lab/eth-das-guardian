package api

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
)

const (
	NodeVersionBase = "eth/v1/node/version"
)

type NodeVersion struct {
	Data struct {
		Version string `json:"version"`
	} `json:"data"`
}

func (c *Client) GetNodeVersion(ctx context.Context) (NodeVersion, error) {
	var version NodeVersion

	resp, err := c.get(ctx, c.cfg.QueryTimeout, NodeVersionBase, "")
	if err != nil {
		return version, errors.Wrap(err, "requesting node-health")
	}

	err = json.Unmarshal(resp, &version)
	if err != nil {
		return version, errors.Wrap(err, "unmarshaling node-health from http request")
	}

	return version, nil
}
