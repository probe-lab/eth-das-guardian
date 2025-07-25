package dora

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
)

var NetworkConsensusClientsBase = "v1/clients/consensus"

// ConsensusClientNodeInfo represents the response structure for consensus client node info
type ConsensusClientNodeInfo struct {
	ClientName         string                   `json:"client_name"`
	ClientType         string                   `json:"client_type"`
	Version            string                   `json:"version"`
	PeerID             string                   `json:"peer_id"`
	NodeID             string                   `json:"node_id"`
	ENR                string                   `json:"enr"`
	HeadSlot           uint64                   `json:"head_slot"`
	HeadRoot           string                   `json:"head_root"`
	Status             string                   `json:"status"`
	PeerCount          uint32                   `json:"peer_count"`
	PeersInbound       uint32                   `json:"peers_inbound"`
	PeersOutbound      uint32                   `json:"peers_outbound"`
	LastRefresh        string                   `json:"last_refresh"`
	LastError          string                   `json:"last_error,omitempty"`
	SupportsDataColumn bool                     `json:"supports_data_column"`
	ColumnIndexes      []uint64                 `json:"column_indexes,omitempty"`
	Metadata           *ConsensusClientMetadata `json:"metadata,omitempty"`
}

// ConsensusClientMetadata represents the metadata from the node identity
type ConsensusClientMetadata struct {
	Attnets           string `json:"attnets,omitempty"`
	Syncnets          string `json:"syncnets,omitempty"`
	SeqNumber         string `json:"seq_number,omitempty"`
	CustodyGroupCount string `json:"custody_group_count,omitempty"` // MetadataV3 field for Fulu
}

// ConsensusClientsResponse represents the full  response
type ConsensusClientsResponse struct {
	Clients []ConsensusClientNodeInfo `json:"clients"`
	Count   int                       `json:"count"`
}

func (c *Client) GetConsensusClients(ctx context.Context) (*ConsensusClientsResponse, error) {
	consensusNodes := &ConsensusClientsResponse{}
	resp, err := c.get(ctx, c.cfg.QueryTimeout, NetworkConsensusClientsBase, "")
	if err != nil {
		return nil, errors.Wrap(err, "requesting network's consensus clients")
	}
	err = json.Unmarshal(resp, &consensusNodes)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling beacon-block from http request")
	}
	return consensusNodes, nil
}
