package dasguardian

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSingleSlotEvaluation(t *testing.T) {
	tests := []struct {
		tag                  string
		slot                 uint64
		bblock               *spec.VersionedSignedBeaconBlock
		reqCols              []uint64
		downloadedCols       []*DataColumnSidecarV1
		expectedDownloads    []string
		expectedValidKzgs    []string
		expectedValidColumns []bool
		expectedValidSlot    bool
	}{
		{
			tag:     "columns downloaded and valid",
			slot:    1,
			bblock:  genSyntheticFuluBlock(1, 2),
			reqCols: []uint64{1, 2, 3},
			downloadedCols: []*DataColumnSidecarV1{
				{
					Index:          1,
					KzgCommitments: generateSyntheticKzgBytes(2),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
				{
					Index:          2,
					KzgCommitments: generateSyntheticKzgBytes(2),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
				{
					Index:          3,
					KzgCommitments: generateSyntheticKzgBytes(2),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
			},
			expectedDownloads:    []string{"2/2", "2/2", "2/2"},
			expectedValidKzgs:    []string{"2/2", "2/2", "2/2"},
			expectedValidColumns: []bool{true, true, true},
			expectedValidSlot:    true,
		},
		{
			tag:     "columns downloaded but missing a column",
			slot:    1,
			bblock:  genSyntheticFuluBlock(1, 2),
			reqCols: []uint64{1, 2, 3},
			downloadedCols: []*DataColumnSidecarV1{
				{
					Index:          1,
					KzgCommitments: generateSyntheticKzgBytes(2),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
				{
					Index:          2,
					KzgCommitments: generateSyntheticKzgBytes(2),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
			},
			expectedDownloads:    []string{"2/2", "2/2", "0/2"},
			expectedValidKzgs:    []string{"2/2", "2/2", "0/2"},
			expectedValidColumns: []bool{true, true, false},
			expectedValidSlot:    false,
		},
		{
			tag:     "columns downloaded 1 incomplete",
			slot:    1,
			bblock:  genSyntheticFuluBlock(1, 2),
			reqCols: []uint64{1, 2, 3},
			downloadedCols: []*DataColumnSidecarV1{
				{
					Index:          1,
					KzgCommitments: generateSyntheticKzgBytes(2),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
				{
					Index:          2,
					KzgCommitments: generateSyntheticKzgBytes(2),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
				{
					Index:          3,
					KzgCommitments: generateSyntheticKzgBytes(1),
					SignedBlockHeader: &phase0.SignedBeaconBlockHeader{
						Message: &phase0.BeaconBlockHeader{
							Slot: phase0.Slot(1),
						},
					},
				},
			},
			expectedDownloads:    []string{"2/2", "2/2", "1/2"},
			expectedValidKzgs:    []string{"2/2", "2/2", "1/2"},
			expectedValidColumns: []bool{true, true, false},
			expectedValidSlot:    false,
		},
		{
			tag:                  "no downloads",
			slot:                 1,
			bblock:               genSyntheticFuluBlock(1, 2),
			reqCols:              []uint64{1, 2, 3},
			downloadedCols:       []*DataColumnSidecarV1{},
			expectedDownloads:    []string{"0/2", "0/2", "0/2"},
			expectedValidKzgs:    []string{"0/2", "0/2", "0/2"},
			expectedValidColumns: []bool{false, false, false},
			expectedValidSlot:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.tag, func(t *testing.T) {
			expDownloads, expValidKzg, validCols, validSlot := evaluateDownloadedColumns(
				logrus.New(),
				test.slot,
				test.bblock,
				test.reqCols,
				test.downloadedCols,
			)
			assert.Equal(t, test.expectedValidSlot, validSlot)
			for i := range validCols {
				assert.Equal(t, test.expectedValidColumns[i], validCols[i])
			}
			for i := range expValidKzg {
				assert.Equal(t, test.expectedValidKzgs[i], expValidKzg[i])
			}
			for i := range expDownloads {
				assert.Equal(t, test.expectedDownloads[i], expDownloads[i])
			}
		})
	}
}

func genSyntheticFuluBlock(slot uint64, blobs uint64) *spec.VersionedSignedBeaconBlock {
	// create the minimal necessary beacon block
	return &spec.VersionedSignedBeaconBlock{
		Version: spec.DataVersionFulu,
		Fulu: &electra.SignedBeaconBlock{
			Message: &electra.BeaconBlock{
				Slot: phase0.Slot(slot),
				Body: &electra.BeaconBlockBody{
					BlobKZGCommitments: generateSyntheticKzgs(blobs),
				},
			},
		},
	}
}

func generateSyntheticKzgs(kzgsCount uint64) []deneb.KZGCommitment {
	kzgs := make([]deneb.KZGCommitment, kzgsCount)
	for i := 0; i < int(kzgsCount); i++ {
		kzgs[i] = generateSyntheticKzg(i)
	}
	return kzgs
}

func generateSyntheticKzg(kzgCount int) deneb.KZGCommitment {
	kzg := make([]byte, 48)
	kzg[kzgCount] = 1
	return deneb.KZGCommitment(kzg[:48])
}

func generateSyntheticKzgBytes(kzgCount int) [][]byte {
	kzgBytes := make([][]byte, kzgCount)
	kzgs := generateSyntheticKzgs(uint64(kzgCount))
	for i, kzg := range kzgs {
		kzgBytes[i] = []byte(kzg[:])
	}
	return kzgBytes
}
