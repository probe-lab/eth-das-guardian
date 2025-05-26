package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"

	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/probe-lab/eth-das-guardian/api"
	log "github.com/sirupsen/logrus"
)

func evaluateColumnResponses(slots []uint64, columnIdxs []uint64, bBlocks []api.BeaconBlock, cols [][]*pb.DataColumnSidecar) error {
	tableHeader := make([]string, 1+len(columnIdxs))
	tableHeader[0] = "slot"
	for i, idx := range columnIdxs {
		tableHeader[i+1] = fmt.Sprintf("col [%d]", idx)
	}

	summaryContent := [][]string{}
	// we assume that both, the cols and the blocks are sorted
	for s, slot := range slots {
		newSummaryRow := make([]string, 1+len(columnIdxs))
		newSummaryRow[0] = fmt.Sprintf("%d", slot)

		// still check it
		if len(cols[s]) == 0 {
			//lint:ignore S1005 complaints all the time
			for i := range columnIdxs {
				newSummaryRow[i+1] = "x"
			}
			log.Warnf(
				"no data cols for slot (data-cols %d) (block %d)",
				bBlocks[s].Data.Message.Body.BlobKZGCommitments,
				len(cols[s]),
			)
			summaryContent = append(summaryContent, newSummaryRow)
			continue
		}

		// not that save
		slot, _ := strconv.Atoi(bBlocks[s].Data.Message.Slot)
		if uint64(slot) != uint64(cols[s][0].SignedBlockHeader.Header.Slot) {
			// we should panic or continue?
			log.Warnf(
				"slot (%d), block (%s) and col (%d) don't match",
				slot,
				bBlocks[s].Data.Message.Slot,
				uint64(cols[s][0].SignedBlockHeader.Header.Slot),
			)
		}

		for c, dataCol := range cols[s] {
			bloclKzgCommitments := bBlocks[s].Data.Message.Body.BlobKZGCommitments
			blobCount := len(bloclKzgCommitments)

			validCommit := 0
			for _, colCom := range dataCol.KzgCommitments {
				for _, kzgCom := range bloclKzgCommitments {
					if compareBytes(colCom, kzgCom[:]) {
						validCommit++
					}
				}
			}

			// TODO: compute validation of the column

			newSummaryRow[c+1] = fmt.Sprintf(
				"blobs (%d/%d) / kzg-cmts (%d/%d/%d)",
				len(dataCol.Column), blobCount,
				validCommit, len(dataCol.KzgCommitments), blobCount,
			)
		}
		summaryContent = append(summaryContent, newSummaryRow)
	}
	// compose the table
	table := tablewriter.NewWriter(os.Stdout)
	table.Header(tableHeader)
	table.Bulk(summaryContent)

	return table.Render()
}

func compareBytes(org, to []byte) (equal bool) {
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
