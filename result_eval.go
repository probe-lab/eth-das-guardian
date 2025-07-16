package dasguardian

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
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
	logger log.FieldLogger,
	nodeID string,
	slots []uint64,
	columnIdxs []uint64,
	bBlocks []*spec.VersionedSignedBeaconBlock,
	cols [][]*DataColumnSidecarV1,
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

	for s := range slots {
		downloaded := make([]string, len(columnIdxs))
		validKzg := make([]string, len(columnIdxs))
		validColumn := make([]bool, len(columnIdxs))
		validSlot := true // true, unless something is not correct
		slot, _ := bBlocks[s].Slot()
		defer func() {
			dasEvalRes.DownloadedResult[s] = downloaded
			dasEvalRes.ValidKzg[s] = validKzg
			dasEvalRes.ValidSlot[s] = validSlot
			dasEvalRes.ValidColumn[s] = validColumn
		}()

		// check if we could actually download anything from the
		blobCount := 0
		if bBlocks[s] != nil {
			kzgCommitments, _ := bBlocks[s].BlobKZGCommitments()
			blobCount = len(kzgCommitments)
		}
		if len(cols[s]) == 0 {
			for i := range columnIdxs {
				downloaded[i] = fmt.Sprintf("0/%d", blobCount)
				validKzg[i] = fmt.Sprintf("0/%d", blobCount)
				validColumn[i] = (blobCount == 0)
			}
			validSlot = (blobCount == 0)
			if blobCount != 0 {
				logger.Errorf(
					"no data cols for slot (downloaded data-cols %d) (block %s)",
					len(cols[s]),
					slot,
				)
			}
			continue
		}

		// check if the received columns match the requested ones
		if uint64(slot) != uint64(cols[s][0].SignedBlockHeader.Message.Slot) {
			logger.Warnf(
				"slot (%d) and col-slot (%d) don't match",
				slot,
				uint64(cols[s][0].SignedBlockHeader.Message.Slot),
			)
			validSlot = false
		}

		// check if the commitments match
		for c, dataCol := range cols[s] {
			blockKzgCommitments, _ := bBlocks[s].BlobKZGCommitments()
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

func (res *DASEvaluationResult) LogVisualization(logger log.FieldLogger) error {
	logger.Info("DAS evaluation for", res.NodeID)
	// we assume that both, the cols and the blocks are sorted
	for s, slot := range res.Slots {
		if res.ValidSlot[s] {
			logger.Infof("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		} else {
			logger.Warnf("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		}
		for c, sum := range res.DownloadedResult[s] {
			if res.ValidColumn[s][c] {
				logger.Infof(
					"slot(%d) col(%d) - data-cols(%s) valid-kzgs(%s)",
					slot,
					res.ColumnIdx[c],
					sum,
					res.ValidKzg[s][c],
				)
			} else {
				logger.Warnf(
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
