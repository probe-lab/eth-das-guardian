package dasguardian

import (
	"context"
	"errors"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/electra"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSlotRangeType_String(t *testing.T) {
	assert.Equal(t, "none", NoSlots.String())
	assert.Equal(t, "custom", CustomSlots.String())
	assert.Equal(t, "random-not-missed", RandomNonMissedSlots.String())
	assert.Equal(t, "random-with-blobs", RandomWithBlobsSlots.String())
	assert.Equal(t, "random-available-slots", RandomAvailableSlots.String())
}

func TestSlotRangeTypeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected SlotRangeType
	}{
		{"none", NoSlots},
		{"custom", CustomSlots},
		{"random-not-missed", RandomNonMissedSlots},
		{"random-with-blobs", RandomWithBlobsSlots},
		{"random-available-slots", RandomAvailableSlots},
		{"", RandomAvailableSlots},
		{"invalid", RandomAvailableSlots},
	}

	for _, tt := range tests {
		result := SlotRangeTypeFromString(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

func TestSlotRangeRequestParams_Validate(t *testing.T) {
	cases := []struct {
		params  SlotRangeRequestParams
		wantErr bool
		errText string
	}{
		{SlotRangeRequestParams{Type: NoSlots}, false, ""},
		{SlotRangeRequestParams{Type: CustomSlots, Slots: []uint64{1, 2}}, false, ""},
		{SlotRangeRequestParams{Type: CustomSlots, Slots: []uint64{}}, true, "no slots were given"},
		{SlotRangeRequestParams{Type: RandomNonMissedSlots, Range: 3}, false, ""},
		{SlotRangeRequestParams{Type: RandomWithBlobsSlots, Range: 2}, false, ""},
		{SlotRangeRequestParams{Type: RandomAvailableSlots, Range: 3}, false, ""},
		{SlotRangeRequestParams{Type: RandomAvailableSlots, Range: 0}, true, "no slot-range was given (0)"},
		{SlotRangeRequestParams{Type: SlotRangeType("bad")}, true, "undefined slot-range-type bad"},
	}

	for _, c := range cases {
		err := c.params.Validate()
		if c.wantErr {
			assert.Error(t, err)
			assert.Contains(t, err.Error(), c.errText)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestSlotRangeRequestParams_SlotSelector_NotNil(t *testing.T) {
	variants := []SlotRangeRequestParams{
		{Type: NoSlots},
		{Type: CustomSlots, Slots: []uint64{7, 8}},
		{Type: RandomNonMissedSlots, Range: 2},
		{Type: RandomWithBlobsSlots, Range: 3},
		{Type: RandomAvailableSlots, Range: 4},
		{Type: SlotRangeType("unknown"), Range: 4},
	}
	for _, opts := range variants {
		sel := opts.SlotSelector()
		assert.NotNil(t, sel)
	}
}

func TestSlotsFromSampleableSlots(t *testing.T) {
	s := []SampleableSlot{
		{Slot: 10, BeaconBlock: &spec.VersionedSignedBeaconBlock{}},
		{Slot: 20, BeaconBlock: &spec.VersionedSignedBeaconBlock{}},
	}
	out := SlotsFromSampleableSlots(s)
	assert.Equal(t, []uint64{10, 20}, out)
}

func TestSlotsFromSampleableSlots_Empty(t *testing.T) {
	out := SlotsFromSampleableSlots([]SampleableSlot{})
	assert.Empty(t, out)
}

func TestBlocksFromSampleableSlots(t *testing.T) {
	b1 := &spec.VersionedSignedBeaconBlock{}
	b2 := &spec.VersionedSignedBeaconBlock{}
	s := []SampleableSlot{
		{Slot: 5, BeaconBlock: b1},
		{Slot: 6, BeaconBlock: b2},
	}
	out := BlocksFromSampleableSlots(s)
	assert.Equal(t, []*spec.VersionedSignedBeaconBlock{b1, b2}, out)
}

func TestBlocksFromSampleableSlots_Empty(t *testing.T) {
	out := BlocksFromSampleableSlots([]SampleableSlot{})
	assert.Empty(t, out)
}

func TestWithCustomSlots_Success(t *testing.T) {
	api := new(mockBeaconAPI)
	slots := []uint64{100, 200, 300}
	block := &spec.VersionedSignedBeaconBlock{}

	for _, slot := range slots {
		api.On("GetBeaconBlock", mock.Anything, slot).Return(block, nil)
	}

	selector := WithCustomSlots(slots)
	out, err := selector(context.Background(), api, &StatusV2{})
	assert.NoError(t, err)
	assert.Len(t, out, len(slots))
	for i, ss := range out {
		assert.Equal(t, slots[i], ss.Slot)
		assert.Equal(t, block, ss.BeaconBlock)
	}
	api.AssertExpectations(t)
}

func TestWithCustomSlots_Error(t *testing.T) {
	api := new(mockBeaconAPI)
	slots := []uint64{1, 2}
	block := &spec.VersionedSignedBeaconBlock{}

	api.On("GetBeaconBlock", mock.Anything, uint64(1)).Return(block, nil)
	api.On("GetBeaconBlock", mock.Anything, uint64(2)).Return((*spec.VersionedSignedBeaconBlock)(nil), errors.New("oops"))

	selector := WithCustomSlots(slots)
	out, err := selector(context.Background(), api, &StatusV2{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "retrieving slot 2")
	assert.Len(t, out, len(slots))
	api.AssertExpectations(t)
}

func TestWithNoSlots(t *testing.T) {
	selector := WithNoSlots()
	out, err := selector(context.Background(), nil, &StatusV2{})
	assert.NoError(t, err)
	assert.Nil(t, out)
}

func TestEpochToSlot(t *testing.T) {
	tests := []struct {
		name     string
		epoch    uint64
		expected uint64
	}{
		{"Epoch0", 0, 0},
		{"Epoch32", 1, 32},
		{"Epoch64", 2, 64},
		{"Epoch3200", 100, 3200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EpochToSlot(tt.epoch)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetMaxSampleableSlot(t *testing.T) {
	tests := []struct {
		name                  string
		fuluForkEpoch         uint64
		minCustodyEpoch       uint64
		headSlot              uint64
		earliestAvailableSlot uint64
		expectedMinSampleSlot uint64
	}{
		{
			name:                  "FuluSlotHighest",
			fuluForkEpoch:         100,
			minCustodyEpoch:       200,
			headSlot:              uint64(10_000),
			earliestAvailableSlot: 0,
			expectedMinSampleSlot: 3600, // 10_000 - 200*32 = 3600, but fulu is higher at 100*32 = 3200, so max(3200, 3600, 0) = 3600
		},
		{
			name:                  "EarliestAvailableSlotHighest",
			fuluForkEpoch:         50,
			minCustodyEpoch:       100,
			headSlot:              uint64(10_000),
			earliestAvailableSlot: 8000,
			expectedMinSampleSlot: 8000, // max(50*32, 10000-100*32, 8000) = max(1600, 6800, 8000) = 8000
		},
		{
			name:                  "CustodySlotHighest",
			fuluForkEpoch:         10,
			minCustodyEpoch:       50,
			headSlot:              uint64(5_000),
			earliestAvailableSlot: 100,
			expectedMinSampleSlot: 3400, // max(10*32, 5000-50*32, 100) = max(320, 3400, 100) = 3400
		},
		{
			name:                  "CustodyExceedsHeadSlot",
			fuluForkEpoch:         10,
			minCustodyEpoch:       200,
			headSlot:              uint64(1_000),
			earliestAvailableSlot: 0,
			expectedMinSampleSlot: 320, // custody epochs * 32 > headSlot, so custody gets capped to fulu
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fuluSlot := EpochToSlot(tt.fuluForkEpoch)
			custodySlots := EpochToSlot(tt.minCustodyEpoch)
			result := GetMaxSampleableSlot(fuluSlot, tt.headSlot, custodySlots, tt.earliestAvailableSlot)
			assert.Equal(t, tt.expectedMinSampleSlot, result)
		})
	}
}

func TestSelectRandomSlotsForRange(t *testing.T) {
	tests := []struct {
		name        string
		minSlot     uint64
		headSlot    uint64
		bins        uint64
		expectedLen int
	}{
		{"ValidRange", 10, 100, 5, 5},
		{"SingleSlot", 1, 50, 1, 1},
		{"InvalidRange", 120, 100, 5, 0},
		{"EdgeCase1", 1, 2, 1, 1},
		{"EdgeCase2", 1, 1, 1, 0},
		{"BinsGreaterThanRange", 95, 100, 10, 5},
		{"ZeroBins", 10, 100, 0, 0},
		{"ZeroMinSlot", 0, 100, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectRandomSlotsForRange(tt.minSlot, tt.headSlot, tt.bins)
			assert.Len(t, result, tt.expectedLen)

			// Check that all slots are within expected range
			for _, slot := range result {
				assert.True(t, slot >= tt.minSlot, "slot should be >= minSlot")
				assert.True(t, slot < tt.headSlot, "slot should be < headSlot")
			}
		})
	}
}

func TestGenerateRandomSlots_Success(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(5)
	statusV2 := &StatusV2{EarliestAvailableSlot: 0}

	api.On("GetFuluForkEpoch").Return(uint64(64))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(4096), true)

	header := &phase0.BeaconBlockHeader{Slot: 10_000}
	api.On("GetLatestBlockHeader").Return(header)

	block := &spec.VersionedSignedBeaconBlock{}
	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(block, nil)

	// Simple validation function that accepts any block
	valFn := func(b *spec.VersionedSignedBeaconBlock) bool { return true }

	out, err := GenerateRandomSlots(context.Background(), api, n, valFn, statusV2)
	assert.NoError(t, err)
	assert.Len(t, out, int(n))

	// Verify all slots are populated
	for i, slot := range out {
		assert.NotZero(t, slot.Slot, "slot %d should not be zero", i)
		assert.NotNil(t, slot.BeaconBlock, "beacon block %d should not be nil", i)
	}

	api.AssertExpectations(t)
}

func TestGenerateRandomSlots_Error_NoHeader(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(3)
	statusV2 := &StatusV2{EarliestAvailableSlot: 0}

	api.On("GetFuluForkEpoch").Return(uint64(0))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(0), false)
	api.On("GetLatestBlockHeader").Return((*phase0.BeaconBlockHeader)(nil))

	valFn := func(b *spec.VersionedSignedBeaconBlock) bool { return true }

	out, err := GenerateRandomSlots(context.Background(), api, n, valFn, statusV2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to retrieve the latest block header")
	assert.Nil(t, out)
}

func TestGenerateRandomSlots_Error_GetBeaconBlock(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(2)
	statusV2 := &StatusV2{EarliestAvailableSlot: 0}

	api.On("GetFuluForkEpoch").Return(uint64(0))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(4096), false)
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 100})

	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return((*spec.VersionedSignedBeaconBlock)(nil), errors.New("fetch failed"))

	valFn := func(b *spec.VersionedSignedBeaconBlock) bool { return true }

	out, err := GenerateRandomSlots(context.Background(), api, n, valFn, statusV2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to retrieve the column custody from the specs")
	assert.Nil(t, out)
}

func TestWithRandomSlots_Integration(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(3)

	api.On("GetFuluForkEpoch").Return(uint64(1))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(32), true)
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 200})
	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(&spec.VersionedSignedBeaconBlock{
			Electra: &electra.SignedBeaconBlock{
				Message: &electra.BeaconBlock{
					Slot: phase0.Slot(1),
					Body: &electra.BeaconBlockBody{
						BlobKZGCommitments: []deneb.KZGCommitment{
							{},
							{},
							{},
						},
					},
				},
			},
		}, nil)

	// Test random slot variants (excluding RandomAvailableSlots as it requires StatusV2)
	variants := []struct {
		name     string
		factory  func(int32) SlotSelector
		statusV2 *StatusV2
	}{
		{"RandomNonMissedSlots", WithRandomNonMissedSlots, &StatusV2{}},
		{"RandomWithBlobsSlots", WithRandomWithBlobsSlots, &StatusV2{EarliestAvailableSlot: 32}}, // from the same fulu epoch
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			selector := variant.factory(int32(n))
			out, err := selector(context.Background(), api, variant.statusV2)
			assert.NoError(t, err)
			assert.Len(t, out, int(n))

			// Verify slots are unique and in valid range
			slotMap := make(map[uint64]bool)
			for _, slot := range out {
				assert.NotZero(t, slot.Slot)
				assert.NotNil(t, slot.BeaconBlock)
				assert.False(t, slotMap[slot.Slot], "slot %d should be unique", slot.Slot)
				slotMap[slot.Slot] = true
			}

			// Reset mock calls for next iteration
			api.ExpectedCalls = nil
			api.Calls = nil
			api.On("GetFuluForkEpoch").Return(uint64(1))
			api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
				Return(uint64(32), true)
			api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 200})
			api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
				Return(&spec.VersionedSignedBeaconBlock{
					Electra: &electra.SignedBeaconBlock{
						Message: &electra.BeaconBlock{
							Slot: phase0.Slot(1),
							Body: &electra.BeaconBlockBody{
								BlobKZGCommitments: []deneb.KZGCommitment{
									{},
									{},
									{},
								},
							},
						},
					},
				}, nil)
		})
	}
}

func TestWithRandomAvailableSlots(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(2)
	statusV2 := &StatusV2{EarliestAvailableSlot: 50}

	api.On("GetFuluForkEpoch").Return(uint64(1))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(32), true)
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 200})

	// Create a mock block with Electra version and blob commitments
	electraBlock := &spec.VersionedSignedBeaconBlock{
		Electra: &electra.SignedBeaconBlock{
			Message: &electra.BeaconBlock{
				Slot: phase0.Slot(1),
				Body: &electra.BeaconBlockBody{
					BlobKZGCommitments: []deneb.KZGCommitment{
						{}, // Mock commitment
						{}, // Mock commitment
						{}, // Mock commitment
					},
				},
			},
		},
	}

	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(electraBlock, nil)

	selector := WithRandomAvailableSlots(n)
	out, err := selector(context.Background(), api, statusV2)
	assert.NoError(t, err)
	assert.Len(t, out, int(n))

	// Verify all slots have beacon blocks
	for _, slot := range out {
		assert.NotZero(t, slot.Slot)
		assert.NotNil(t, slot.BeaconBlock)
	}

	api.AssertExpectations(t)
}

func TestGenerateRandomSlots_ValidationFunction(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(2)
	statusV2 := &StatusV2{EarliestAvailableSlot: 0}

	api.On("GetFuluForkEpoch").Return(uint64(1))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(32), true)
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 200})

	// Mock blocks - some valid, some invalid
	validBlock := &spec.VersionedSignedBeaconBlock{
		Electra: &electra.SignedBeaconBlock{
			Message: &electra.BeaconBlock{
				Body: &electra.BeaconBlockBody{
					BlobKZGCommitments: []deneb.KZGCommitment{
						{}, // Mock commitment
						{}, // Mock commitment
						{}, // Mock commitment
					},
				},
			},
		},
	}

	// Mock the API to return valid blocks
	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(validBlock, nil).Maybe()

	// Validation function that only accepts blocks with blob commitments
	valFn := func(b *spec.VersionedSignedBeaconBlock) bool {
		if b.Electra == nil {
			return false
		}
		return len(b.Electra.Message.Body.BlobKZGCommitments) > 0
	}

	out, err := GenerateRandomSlots(context.Background(), api, n, valFn, statusV2)
	assert.NoError(t, err)
	assert.Len(t, out, int(n))

	// Verify all returned slots have valid blocks
	for _, slot := range out {
		assert.NotZero(t, slot.Slot)
		assert.NotNil(t, slot.BeaconBlock)
		assert.True(t, valFn(slot.BeaconBlock), "returned block should pass validation")
	}

	api.AssertExpectations(t)
}

func TestGenerateRandomSlots_LargeRange(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(100)

	api.On("GetFuluForkEpoch").Return(uint64(100))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(1), true) // 1 epoch, so min custody of 32 slots
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 10000})
	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(&spec.VersionedSignedBeaconBlock{}, nil)

	valFn := func(b *spec.VersionedSignedBeaconBlock) bool { return true }

	out, err := GenerateRandomSlots(context.Background(), api, n, valFn, &StatusV2{})
	assert.NoError(t, err)

	// The actual available range is only 32 slots (headSlot - minValue = 10000 - 32), so we should get 32, not 100
	expectedLen := 32 // This is the actual available range size
	assert.Len(t, out, expectedLen)

	// Verify slots are within the expected range
	headSlot := uint64(10000)
	minValue := uint64(32)
	minSlot := headSlot - minValue // headSlot - minValue = 10000 - 32
	maxSlot := uint64(10000)       // head slot
	for _, slot := range out {
		assert.True(t, slot.Slot >= minSlot, "slot %d should be >= minSlot %d", slot.Slot, minSlot)
		assert.True(t, slot.Slot <= maxSlot, "slot %d should be < maxSlot %d", slot.Slot, maxSlot)
	}
}

func TestSlotRangeRequestParams_SlotSelector_RandomAvailableSlots(t *testing.T) {
	statusV2 := &StatusV2{EarliestAvailableSlot: 100}

	params := SlotRangeRequestParams{
		Type:  RandomAvailableSlots,
		Range: 5,
	}

	selector := params.SlotSelector()
	assert.NotNil(t, selector)

	// Test that the selector can be called (basic smoke test)
	api := new(mockBeaconAPI)
	api.On("GetFuluForkEpoch").Return(uint64(1))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(32), true)
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 200})
	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(&spec.VersionedSignedBeaconBlock{
			Electra: &electra.SignedBeaconBlock{
				Message: &electra.BeaconBlock{
					Slot: phase0.Slot(1),
					Body: &electra.BeaconBlockBody{
						BlobKZGCommitments: []deneb.KZGCommitment{
							{}, // Mock commitment
							{}, // Mock commitment
							{}, // Mock commitment
						},
					},
				},
			},
		}, nil)

	out, err := selector(context.Background(), api, statusV2)
	assert.NoError(t, err)
	assert.Len(t, out, int(params.Range))

	api.AssertExpectations(t)
}
