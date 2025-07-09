package api

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/pkg/errors"
)

var NodeIdentityBase = "eth/v1/node/identity"

type NodeIdentity struct {
	Data struct {
		PeerID     string   `json:"peer_id"`
		Enr        string   `json:"enr"`
		Maddrs     []string `json:"p2p_addresses"`
		DiscvAddrs []string `json:"discovery_addresses"`
		Metadata   struct {
			SeqNum   string `json:"seq_number"`
			Attnets  string `json:"attnets"`
			Syncnets string `json:"syncnets"`
			Cgc      string `json:"custody_group_count"`
		} `json:"metadata"`
	} `json:"data"`
}

func (i *NodeIdentity) CustodyInt() (int, error) {
	return strconv.Atoi(i.Data.Metadata.Cgc)
}

func (i *NodeIdentity) Attnets() string {
	return i.Data.Metadata.Attnets
}

func (i *NodeIdentity) Syncnets() string {
	return i.Data.Metadata.Syncnets
}

func (c *Client) GetNodeIdentity(ctx context.Context) (*NodeIdentity, error) {
	var nodeIdentity NodeIdentity
	resp, err := c.get(ctx, c.cfg.QueryTimeout, NodeIdentityBase, "")
	if err != nil {
		return nil, errors.Wrap(err, "requesting node-identity")
	}
	err = json.Unmarshal(resp, &nodeIdentity)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling node-identity from http request")
	}
	return &nodeIdentity, nil
}
