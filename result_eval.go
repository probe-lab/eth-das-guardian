package dasguardian

import (
	"fmt"
	"strconv"

	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/probe-lab/eth-das-guardian/api"
	log "github.com/sirupsen/logrus"
)

type DASEvaluationResult struct {
	NodeID           string
	Slots            []uint64
	ColumnIdx        []uint64
	DownloadedResult [][]string
	ValidKzg         [][]bool
	ValidSlot        []bool
	Error            error
}

func evaluateColumnResponses(
	nodeID string,
	slots []uint64,
	columnIdxs []uint64,
	bBlocks []api.BeaconBlock,
	cols [][]*pb.DataColumnSidecar,
) (DASEvaluationResult, error) {
	dasEvalRes := DASEvaluationResult{
		NodeID:           nodeID,
		Slots:            slots,
		ColumnIdx:        columnIdxs,
		DownloadedResult: make([][]string, len(slots)),
		ValidKzg:         make([][]bool, len(slots)),
		ValidSlot:        make([]bool, len(slots)),
	}

	for s, _ := range slots {
		downloaded := make([]string, len(columnIdxs))
		validDownload := make([]bool, len(columnIdxs))
		validKzg := make([]bool, len(columnIdxs))
		validSlot := true // true, unless something is not correct
		defer func() {
			dasEvalRes.DownloadedResult[s] = downloaded
			dasEvalRes.ValidKzg[s] = validKzg
			dasEvalRes.ValidSlot[s] = validSlot
		}()

		// check if we could actually download anything from the
		if len(cols[s]) == 0 {
			//lint:ignore S1005 complaints all the time
			for i := range columnIdxs {
				downloaded[i] = fmt.Sprintf("0/%d", len(columnIdxs))
				validDownload[i] = false
				validKzg[i] = false

			}
			validSlot = false
			log.Errorf(
				"no data cols for slot (data-cols %d) (block %s)",
				len(cols[s]),
				bBlocks[s].Data.Message.Slot,
			)
			continue
		}

		// check if the received columns match the requested ones
		slot, _ := strconv.Atoi(bBlocks[s].Data.Message.Slot)
		if uint64(slot) != uint64(cols[s][0].SignedBlockHeader.Header.Slot) {
			log.Warnf(
				"slot (%d), block (%s) and col (%d) don't match",
				slot,
				bBlocks[s].Data.Message.Slot,
				uint64(cols[s][0].SignedBlockHeader.Header.Slot),
			)
			validSlot = false
		}

		// check if the commitments match
		for c, dataCol := range cols[s] {
			bloclKzgCommitments := bBlocks[s].Data.Message.Body.BlobKZGCommitments
			invalidCom := 0
			for _, colCom := range dataCol.KzgCommitments {
				for _, kzgCom := range bloclKzgCommitments {
					if matchingBytes(colCom, kzgCom[:]) {
						validKzg[c] = true
					} else {
						validKzg[c] = false
						validSlot = false
						invalidCom++
					}
				}
			}
			downloaded[c] = fmt.Sprintf("%d/%d", len(cols[s])/invalidCom, len(cols[s]))
		}
	}
	// compose the table
	return dasEvalRes, nil
}

func matchingBytes(org, to []byte) (equal bool) {
	if len(org) != len(to) {
		equal = false
		return
	}
	for i, b := range org {
		if b != to[i] {
			equal = false
			return
		}
	}
	return true
}

func (res *DASEvaluationResult) TableVisualization() error {
	log.Info("DAS evaluation for", res.NodeID)
	// we assume that both, the cols and the blocks are sorted
	for s, slot := range res.Slots {
		if res.ValidSlot[s] {
			log.Infof("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		} else {
			log.Warnf("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		}
		for c, sum := range res.DownloadedResult[s] {
			if countTrues(res.ValidKzg[s]) == len(res.ValidKzg[s]) {
				log.Infof(
					"col (%d) - data-cols(%s) / kzg(%d/%d)",
					res.ColumnIdx[c],
					sum,
					countTrues(res.ValidKzg[s]), len(res.ValidKzg[s]),
				)
			} else {
				log.Warnf(
					"col (%d) - data-cols(%s) / kzg(%d/%d)",
					res.ColumnIdx[c],
					sum,
					countTrues(res.ValidKzg[s]), len(res.ValidKzg[s]),
				)
			}
		}
	}
	// compose the table
	return nil
}

func countTrues(vs []bool) (trues int) {
	for _, v := range vs {
		if v {
			trues++
		}
	}
	return trues
}
