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
	ValidKzg         [][]string
	ValidColumn      [][]bool
	ValidSlot        []bool
	Error            error
}

func evaluateColumnResponses(
	nodeID string,
	slots []uint64,
	columnIdxs []uint64,
	bBlocks []*api.BeaconBlock,
	cols [][]*pb.DataColumnSidecar,
) (DASEvaluationResult, error) {
	dasEvalRes := DASEvaluationResult{
		NodeID:           nodeID,
		Slots:            slots,
		ColumnIdx:        columnIdxs,
		DownloadedResult: make([][]string, len(slots)),
		ValidKzg:         make([][]string, len(slots)),
		ValidColumn:      make([][]bool, len(slots)),
		ValidSlot:        make([]bool, len(slots)),
	}

	for s, _ := range slots {
		downloaded := make([]string, len(columnIdxs))
		validKzg := make([]string, len(columnIdxs))
		validColumn := make([]bool, len(columnIdxs))
		validSlot := true // true, unless something is not correct
		defer func() {
			dasEvalRes.DownloadedResult[s] = downloaded
			dasEvalRes.ValidKzg[s] = validKzg
			dasEvalRes.ValidSlot[s] = validSlot
			dasEvalRes.ValidColumn[s] = validColumn
		}()

		// check if we could actually download anything from the
		blobCount := 0
		if bBlocks[s] != nil {
			blobCount = len(bBlocks[s].Data.Message.Body.BlobKZGCommitments)
		}
		if len(cols[s]) == 0 {
			//lint:ignore S1005 complaints all the time
			for i := range columnIdxs {
				downloaded[i] = fmt.Sprintf("0/%d", blobCount)
				validKzg[i] = fmt.Sprintf("0/%d", blobCount)
				validColumn[i] = (blobCount == 0)
			}
			validSlot = (blobCount == 0)
			if blobCount != 0 {
				log.Errorf(
					"no data cols for slot (downloaded data-cols %d) (block %s)",
					len(cols[s]),
					bBlocks[s].Data.Message.Slot,
				)
			}
			continue
		}

		// check if the received columns match the requested ones
		slot, _ := strconv.Atoi(bBlocks[s].Data.Message.Slot)
		if uint64(slot) != uint64(cols[s][0].SignedBlockHeader.Header.Slot) {
			log.Warnf(
				"slot (%d), block (%s) and col-slot (%d) don't match",
				slot,
				bBlocks[s].Data.Message.Slot,
				uint64(cols[s][0].SignedBlockHeader.Header.Slot),
			)
			validSlot = false
		}

		// check if the commitments match
		for c, dataCol := range cols[s] {
			blockKzgCommitments := bBlocks[s].Data.Message.Body.BlobKZGCommitments
			validCom := 0
			for _, colCom := range dataCol.KzgCommitments {
			kzgCheckLoop:
				for _, kzgCom := range blockKzgCommitments {
					if matchingBytes(colCom[:], kzgCom[:]) {
						validCom++
						break kzgCheckLoop
					}
				}
			}
			validKzg[c] = fmt.Sprintf("%d/%d", validCom, len(blockKzgCommitments))
			downloaded[c] = fmt.Sprintf("%d/%d", len(dataCol.KzgCommitments), len(blockKzgCommitments))
			validColumn[c] = (len(blockKzgCommitments) == validCom)
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

func (res *DASEvaluationResult) LogVisualization() error {
	log.Info("DAS evaluation for", res.NodeID)
	// we assume that both, the cols and the blocks are sorted
	for s, slot := range res.Slots {
		if res.ValidSlot[s] {
			log.Infof("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		} else {
			log.Warnf("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		}
		for c, sum := range res.DownloadedResult[s] {
			if res.ValidColumn[s][c] {
				log.Infof(
					"slot(%d) col(%d) - data-cols(%s) valid-kzgs(%s)",
					slot,
					res.ColumnIdx[c],
					sum,
					res.ValidKzg[s][c],
				)
			} else {
				log.Warnf(
					"slot(%d) col(%d) - data-cols(%s) valid-kzgs(%s)",
					slot,
					res.ColumnIdx[c],
					sum,
					res.ValidKzg[s][c],
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
