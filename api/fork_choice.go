package api

import (
	"context"
	"encoding/json"

	"github.com/pkg/errors"
)

var ForkChoiceBase = "eth/v1/debug/fork_choice"

type ForkChoice struct {
	JustifiedCheckpoint Checkpoint       `json:"justified_checkpoint"`
	FinalizedCheckpoint Checkpoint       `json:"finalized_checkpoint"`
	ForkChoiceNodes     []ForkChoiceNode `json:"fork_choice_nodes"`
}

type Checkpoint struct {
	Epoch string `json:"epoch"`
	Root  string `json:"root"`
}

type ForkChoiceNode struct {
	Slot               string `json:"slot"`
	BlockRoot          string `json:"block_root"`
	ParentRoot         string `json:"parent_root"`
	JustifiedEpoch     string `json:"justified_epoch"`
	FinalizedEpoch     string `json:"finalized_epoch"`
	Weight             string `json:"weight"`
	Validity           string `json:"validity"`
	ExecutionBlockHash string `json:"execution_block_hash"`
}

func (c *Client) GetForkChoice(ctx context.Context) (ForkChoice, error) {
	var forkChoice ForkChoice

	resp, err := c.get(ctx, c.cfg.QueryTimeout, ForkChoiceBase, "")
	if err != nil {
		return forkChoice, errors.Wrap(err, "requesting fork-choice")
	}

	err = json.Unmarshal(resp, &forkChoice)
	if err != nil {
		return forkChoice, errors.Wrap(err, "unmarshaling fork-choice from http request")
	}

	return forkChoice, nil
}
