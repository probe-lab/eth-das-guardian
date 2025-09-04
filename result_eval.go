package dasguardian

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
	log "github.com/sirupsen/logrus"
)

type DASEvaluationResult struct {
	NodeID      string
	Slots       []uint64
	ColumnIdx   []uint64
	RangeResult []RPCRequestResult
	RootResult  []RPCRequestResult
	ValidSlot   []bool
	Error       error
}

type RPCRequestResult struct {
	DownloadResult []string
	ValidKzg       []string
	ValidColumn    []bool
	ValidSlot      bool
}

func evaluateColumnResponses(
	logger log.FieldLogger,
	nodeID string,
	sampleableSlots []SampleableSlot,
	columnIdxs []uint64,
	rangeCols [][]*DataColumnSidecarV1,
	rootCols [][]*DataColumnSidecarV1,
) (DASEvaluationResult, error) {
	slots := SlotsFromSampleableSlots(sampleableSlots)
	bBlocks := BlocksFromSampleableSlots(sampleableSlots)

	dasEvalRes := DASEvaluationResult{
		NodeID:      nodeID,
		Slots:       slots,
		ColumnIdx:   columnIdxs,
		RangeResult: make([]RPCRequestResult, len(slots)),
		RootResult:  make([]RPCRequestResult, len(slots)),
		ValidSlot:   make([]bool, len(slots)),
	}

	for i, s := range slots {
		bblock := bBlocks[i]
		// check the range RPCs
		rpcResult := RPCRequestResult{}
		down, validKzgs, validColumns, rangeValidSlot := evaluateDownloadedColumns(
			logger,
			s,
			bblock,
			columnIdxs,
			rangeCols[i],
		)
		rpcResult.DownloadResult = down
		rpcResult.ValidKzg = validKzgs
		rpcResult.ValidColumn = validColumns
		rpcResult.ValidSlot = rangeValidSlot
		dasEvalRes.RangeResult[i] = rpcResult

		// check the root RPCs
		rpcResult = RPCRequestResult{}
		down, validKzgs, validColumns, rootValidSlot := evaluateDownloadedColumns(
			logger,
			s,
			bblock,
			columnIdxs,
			rangeCols[i],
		)
		rpcResult.DownloadResult = down
		rpcResult.ValidKzg = validKzgs
		rpcResult.ValidColumn = validColumns
		rpcResult.ValidSlot = rootValidSlot
		dasEvalRes.RootResult[i] = rpcResult

		// judge validity of the slot
		dasEvalRes.ValidSlot[i] = rangeValidSlot && rootValidSlot
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

func evaluateDownloadedColumns(
	logger log.FieldLogger,
	slot uint64,
	bblock *spec.VersionedSignedBeaconBlock,
	reqCols []uint64,
	downloadedCols []*DataColumnSidecarV1,
) ([]string, []string, []bool, bool) {
	// define the evaluation result variables
	downloadedCells := make([]string, len(reqCols))
	validKzg := make([]string, len(reqCols))
	validColumn := make([]bool, len(reqCols))
	validSlot := true // true, unless something is not correct

	// check if we could actually download anything from the
	if bblock == nil {
		// TODO: reconsider if an empty block is valid or not
		logger.Warnf("unable bblock for slot %d is empty", slot)
		return downloadedCells, validKzg, validColumn, validSlot
	}
	kzgCommitments, err := bblock.BlobKZGCommitments()
	if err != nil {
		logger.Warnf("unable to retrieve kzg commitmets from bblock %d: %v", slot, err)
		return downloadedCells, validKzg, validColumn, validSlot
	}
	blobCount := len(kzgCommitments)
	if blobCount == 0 {
		return downloadedCells, validKzg, validColumn, validSlot
	}
	// check each of the Columns
	// assume that all the cols are in order, and compare the kzg commitments from the bblock
	// with the ones of the columns that we got throught the RPCs
	for c := range reqCols {
		downloadedCellsCount := 0
		validCol := false
		validKzgCount := 0
		if c < len(downloadedCols) {
			for _, cellKzg := range downloadedCols[c].KzgCommitments {
				downloadedCellsCount++
			kzgCheckLoop:
				for _, kzgCom := range kzgCommitments {
					if matchingBytes(cellKzg[:], kzgCom[:]) {
						validKzgCount++
						break kzgCheckLoop
					}
				}
			}
			// if we have as many valid KZG as blobs in the block -> is a valid column
			validCol = (blobCount == validKzgCount)
		}
		downloadedCells[c] = fmt.Sprintf("%d/%d", downloadedCellsCount, blobCount)
		validKzg[c] = fmt.Sprintf("%d/%d", validKzgCount, blobCount)
		validColumn[c] = validCol
		if !validCol {
			validSlot = false
		}
	}
	if len(downloadedCols) > 0 {
		if uint64(slot) != uint64(downloadedCols[0].SignedBlockHeader.Message.Slot) {
			log.Warnf(
				"slot (%d) and col-slot (%d) don't match",
				slot,
				uint64(downloadedCols[0].SignedBlockHeader.Message.Slot),
			)
			validSlot = false
		}
	}

	return downloadedCells, validKzg, validColumn, validSlot
}

func (res *DASEvaluationResult) LogVisualization(logger *log.Logger) error {
	if res.Slots == nil {
		return nil
	}
	logger.Info("DAS evaluation for", res.NodeID)
	// we assume that both, the cols and the blocks are sorted
	for s, slot := range res.Slots {
		if res.ValidSlot[s] {
			logger.Infof("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		} else {
			logger.Warnf("slot (%d) valid (%t):\n", slot, res.ValidSlot[s])
		}
		for colIdx, downloadedResult := range res.RangeResult[s].DownloadResult {
			// log RangeResults
			if res.RangeResult[s].ValidSlot {
				logger.Infof(
					"range req: slot(%d) col(%d) - data-cols(%s) valid-kzgs(%s)",
					slot,
					res.ColumnIdx[colIdx],
					downloadedResult,
					res.RangeResult[s].ValidKzg[colIdx],
				)
			} else {
				logger.Warnf(
					"slot(%d) col(%d) - data-cols(%s) valid-kzgs(%s)",
					slot,
					res.ColumnIdx[colIdx],
					downloadedResult,
					res.RangeResult[s].ValidKzg[colIdx],
				)
			}
			// log RootResults
			if res.RootResult[s].ValidSlot {
				logger.Infof(
					"root req: slot(%d) col(%d) - data-cols(%s) valid-kzgs(%s)",
					slot,
					res.ColumnIdx[colIdx],
					res.RootResult[s].DownloadResult[colIdx],
					res.RootResult[s].ValidKzg[colIdx],
				)
			} else {
				logger.Warnf(
					"slot(%d) col(%d) - data-cols(%s) valid-kzgs(%s)",
					slot,
					res.ColumnIdx[colIdx],
					res.RootResult[s].DownloadResult[colIdx],
					res.RootResult[s].ValidKzg[colIdx],
				)
			}

		}
	}
	// compose the table
	return nil
}
