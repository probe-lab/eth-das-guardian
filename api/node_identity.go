package api

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/ethereum/go-ethereum/common/hexutil"
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
			SeqNum   string        `json:"seq_number"`
			Attnets  hexutil.Bytes `json:"attnets"`
			Syncnets hexutil.Bytes `json:"syncnets"`
			Cgc      string        `json:"custody_group_count"`
		} `json:"metadata"`
	} `json:"data"`
}

func (i *NodeIdentity) CustodyInt() (int, error) {
	// TODO remove patch for Prysm, adding dummy data in missing fields.
	// https://github.com/OffchainLabs/prysm/pull/15506
	if i.Data.Metadata.Cgc == "" {
		return 128, nil
	}
	return strconv.Atoi(i.Data.Metadata.Cgc)
}

func (i *NodeIdentity) Attnets() []byte {
	return i.Data.Metadata.Attnets
}

func (i *NodeIdentity) Syncnets() []byte {
	// TODO remove patch for Prysm, adding dummy data in missing fields.
	// https://github.com/OffchainLabs/prysm/pull/15506
	if i.Data.Metadata.Syncnets == nil {
		return []byte{0x00}
	}
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
