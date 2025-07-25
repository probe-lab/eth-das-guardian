package dora

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pkg/errors"
)

var EpochV1Base = "v1/epoch/%s"

type EpochResponseV1 struct {
	Epoch                   uint64 `json:"epoch"`
	Ts                      uint64 `json:"ts"`
	AttestationsCount       uint64 `json:"attestationscount"`
	AttesterSlashingsCount  uint64 `json:"attesterslashingscount"`
	AverageValidatorBalance uint64 `json:"averagevalidatorbalance"`
	BlocksCount             uint64 `json:"blockscount"`
	DepositsCount           uint64 `json:"depositscount"`
	EligibleEther           uint64 `json:"eligibleether"`
	Finalized               bool   `json:"finalized"`
	GlobalParticipationRate uint64 `json:"globalparticipationrate"`
	MissedBlocks            uint64 `json:"missedblocks"`
	OrphanedBlocks          uint64 `json:"orphanedblocks"`
	ProposedBlocks          uint64 `json:"proposedblocks"`
	ProposerSlashingsCount  uint64 `json:"proposerslashingscount"`
	ScheduledBlocks         uint64 `json:"scheduledblocks"`
	TotalValidatorBalance   uint64 `json:"totalvalidatorbalance"`
	ValidatorsCount         uint64 `json:"validatorscount"`
	VoluntaryExitsCount     uint64 `json:"voluntaryexitscount"`
	VotedEther              uint64 `json:"votedether"`
	RewardsExported         uint64 `json:"rewards_exported"`
	WithdrawalCount         uint64 `json:"withdrawalcount"`
}

func (c *Client) GetEpochV1(ctx context.Context, epochReq string) (*EpochResponseV1, error) {
	epoch := &EpochResponseV1{}
	if epochReq == "" {
		epochReq = "latest"
	}
	resp, err := c.get(ctx, c.cfg.QueryTimeout, fmt.Sprintf(EpochV1Base, epochReq), "")
	if err != nil {
		return nil, errors.Wrap(err, "requesting network's ")
	}
	err = json.Unmarshal(resp, &epoch)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling beacon-block from http request")
	}
	return epoch, nil
}
