package dasguardian

import (
	"context"
	"errors"
	"testing"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestSlotRangeType_String(t *testing.T) {
	assert.Equal(t, "none", NoSlots.String())
	assert.Equal(t, "custom", CustomSlots.String())
	assert.Equal(t, "random", RandomSlots.String())
	assert.Equal(t, "random-not-missed", RandomNonMissedSlots.String())
	assert.Equal(t, "random-with-blobs", RandomWithBlobsSlots.String())
}

func TestSlotRangeTypeFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected SlotRangeType
	}{
		{"none", NoSlots},
		{"custom", CustomSlots},
		{"random", RandomSlots},
		{"random-not-missed", RandomNonMissedSlots},
		{"random-with-blobs", RandomWithBlobsSlots},
		{"", RandomSlots},
		{"invalid", RandomSlots},
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
		{SlotRangeRequestParams{Type: CustomSlots, Slots: []uint64{}}, true, "no slots where given"},
		{SlotRangeRequestParams{Type: RandomSlots, Range: 5}, false, ""},
		{SlotRangeRequestParams{Type: RandomSlots, Range: 0}, true, "no slot-range was given (0)"},
		{SlotRangeRequestParams{Type: RandomNonMissedSlots, Range: 3}, false, ""},
		{SlotRangeRequestParams{Type: RandomWithBlobsSlots, Range: 2}, false, ""},
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
		{Type: RandomSlots, Range: 1},
		{Type: RandomNonMissedSlots, Range: 2},
		{Type: RandomWithBlobsSlots, Range: 3},
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
	out, err := selector(context.Background(), api)
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
	out, err := selector(context.Background(), api)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "retrieving slot 2")
	assert.Len(t, out, len(slots))
	api.AssertExpectations(t)
}

func TestWithNoSlots(t *testing.T) {
	selector := WithNoSlots()
	out, err := selector(context.Background(), nil)
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
		minCustodyExists      bool
		expectedMinSampleSlot uint64
	}{
		{
			name:                  "FuluSlotLower",
			fuluForkEpoch:         100,
			minCustodyEpoch:       200,
			minCustodyExists:      true,
			headSlot:              uint64(10_000),
			expectedMinSampleSlot: 3600, // 10_000 - 100*32
		},
		{
			name:                  "MinCustodySlotLower",
			fuluForkEpoch:         200,
			minCustodyEpoch:       100,
			minCustodyExists:      true,
			headSlot:              uint64(10_000),
			expectedMinSampleSlot: 6800, // 10_000 - 100*32
		},
		{
			name:                  "MinCustodyNotExists",
			fuluForkEpoch:         100,
			minCustodyEpoch:       1,
			minCustodyExists:      false,
			headSlot:              uint64(10_000),
			expectedMinSampleSlot: 9968, // 10_000 - 32
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fuluSlot := EpochToSlot(tt.fuluForkEpoch)
			result := GetMaxSampleableSlot(fuluSlot, tt.headSlot, EpochToSlot(tt.minCustodyEpoch))
			assert.Equal(t, tt.expectedMinSampleSlot, result)
		})
	}
}

func TestSelectRandomSlotsForRange(t *testing.T) {
	tests := []struct {
		name        string
		minSlot     int64
		headSlot    int64
		bins        int64
		expectedLen int
	}{
		{"ValidRange", 10, 100, 5, 5},
		{"SingleSlot", 1, 50, 1, 1},
		{"InvalidRange", 120, 100, 5, 0},
		{"EdgeCase1", 1, 2, 1, 1},
		{"EdgeCase2", 1, 1, 1, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectRandomSlotsForRange(tt.minSlot, tt.headSlot, tt.bins)
			assert.Len(t, result, tt.expectedLen)

			// Check that all slots are within expected range
			for _, slot := range result {
				assert.True(t, int64(slot) >= tt.headSlot-(tt.headSlot-tt.minSlot), "slot should be within [minSlot, headSlot]")
				assert.True(t, int64(slot) <= tt.headSlot, "slot should be <= headSlot")
			}
		})
	}
}

func TestSelectRandomSlotsForRange_EdgeCases(t *testing.T) {
	// Test edge cases that might cause issues
	result := selectRandomSlotsForRange(0, 100, 5)
	assert.Len(t, result, 0)

	result = selectRandomSlotsForRange(10, 5, 3) // minValue > headSlot
	assert.Len(t, result, 0)                     // function should return 0 slots
}

func TestGenerateRandomSlots_Success(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(5)

	api.On("GetFuluForkEpoch").Return(uint64(64))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(4096), true)

	header := &phase0.BeaconBlockHeader{Slot: 10_000}
	api.On("GetLatestBlockHeader").Return(header)

	block := &spec.VersionedSignedBeaconBlock{}
	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(block, nil)

	out, err := GenerateRandomSlots(context.Background(), api, n)
	assert.NoError(t, err)

	// The available range is only 32 slots (10_000 - 2048)
	expectedLen := 5
	assert.Len(t, out, expectedLen)

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

	api.On("GetFuluForkEpoch").Return(uint64(0))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(0), false)
	api.On("GetLatestBlockHeader").Return((*phase0.BeaconBlockHeader)(nil))

	out, err := GenerateRandomSlots(context.Background(), api, n)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to retrieve the latest block header")
	assert.Len(t, out, 0) // no slot should be expected
}

func TestGenerateRandomSlots_Error_GetBeaconBlock(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(2)

	api.On("GetFuluForkEpoch").Return(uint64(0))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(4096), false)
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 100})

	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return((*spec.VersionedSignedBeaconBlock)(nil), errors.New("fetch failed"))

	out, err := GenerateRandomSlots(context.Background(), api, n)
	assert.Contains(t, err.Error(), "unable to retrieve the column custody from the specs")
	assert.Nil(t, out) // no blocks are expected as it failed
}

func TestWithRandomSlots_Integration(t *testing.T) {
	api := new(mockBeaconAPI)
	n := int32(3)

	api.On("GetFuluForkEpoch").Return(uint64(1))
	api.On("ReadSpecParameter", "MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS").
		Return(uint64(32), true)
	api.On("GetLatestBlockHeader").Return(&phase0.BeaconBlockHeader{Slot: 200})
	api.On("GetBeaconBlock", mock.Anything, mock.AnythingOfType("uint64")).
		Return(&spec.VersionedSignedBeaconBlock{}, nil)

	// Test all random slot variants
	variants := []struct {
		name    string
		factory func(int32) SlotSelector
	}{
		{"RandomSlots", WithRandomSlots},
		{"RandomNonMissedSlots", WithRandomNonMissedSlots},
		{"RandomWithBlobsSlots", WithRandomWithBlobsSlots},
	}

	for _, variant := range variants {
		t.Run(variant.name, func(t *testing.T) {
			selector := variant.factory(n)
			out, err := selector(context.Background(), api)
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
				Return(&spec.VersionedSignedBeaconBlock{}, nil)
		})
	}
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

	out, err := GenerateRandomSlots(context.Background(), api, n)
	assert.NoError(t, err)

	// The actual available range is only 32 slots (10000 - 9968), so we should get 32, not 100
	expectedLen := 32 // This is the actual available range size
	assert.Len(t, out, expectedLen)

	// Verify slots are within the expected range
	minSlot := uint64(9968)  // headSlot - minValue = 10000 - 32
	maxSlot := uint64(10000) // head slot
	for _, slot := range out {
		assert.True(t, slot.Slot >= minSlot, "slot %d should be >= minSlot %d", slot.Slot, minSlot)
		assert.True(t, slot.Slot < maxSlot, "slot %d should be < maxSlot %d", slot.Slot, maxSlot)
	}
}

func TestSelectRandomSlotsForRange_Simplified(t *testing.T) {
	tests := []struct {
		name        string
		minSlot     int64
		headSlot    int64
		bins        int64
		expectedLen int
	}{
		{"ValidRange", 10, 100, 5, 5},
		{"SingleSlot", 1, 50, 1, 1},
		{"BinsGreaterThanRange", 95, 100, 10, 5},
		{"ZeroBins", 10, 100, 0, 0},
		{"ZeroMinValue", 0, 100, 5, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := selectRandomSlotsForRange(tt.minSlot, tt.headSlot, tt.bins)
			assert.Len(t, result, tt.expectedLen)

			// Check that all slots are within expected range
			for _, slot := range result {
				assert.True(t, int64(slot) >= tt.headSlot-(tt.headSlot-tt.minSlot),
					"slot %d should be >= %d", slot, tt.headSlot-(tt.headSlot-tt.minSlot))
				assert.True(t, int64(slot) < tt.headSlot,
					"slot %d should be < %d", slot, tt.headSlot)
			}
		})
	}
}
