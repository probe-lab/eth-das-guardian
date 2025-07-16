package dasguardian

import (
	"context"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec"
)

const (
	SLOTS_PER_EPOCH = 32
)

type SlotRangeType string

func (s SlotRangeType) String() string { return string(s) }

const (
	CustomSlots          SlotRangeType = "custom"
	RandomSlots          SlotRangeType = "random"
	RandomNonMissedSlots SlotRangeType = "random-not-missed"
	RandomWithBlobsSlots SlotRangeType = "random-with-blobs"
)

func SlotRangeTypeFromString(s string) SlotRangeType {
	switch s {
	case CustomSlots.String():
		return CustomSlots
	case RandomSlots.String():
		return RandomSlots
	case RandomNonMissedSlots.String():
		return RandomNonMissedSlots
	case RandomWithBlobsSlots.String():
		return RandomWithBlobsSlots
	default:
		return RandomSlots
	}
}

type SlotsToRequest struct {
	Type string
}

// SlotSelector is tha main option interface to define which kind of slots we want to select
// NOTE: all the slots need to be over the fulu fork, otherwise we can't request DataColums
type SlotSelector func(context.Context, *DasGuardian) ([]SampleableSlot, error)

type SampleableSlot struct {
	Slot        uint64
	BeaconBlock *spec.VersionedSignedBeaconBlock
}

func SlotsFromSampleableSlots(ss []SampleableSlot) []uint64 {
	slots := make([]uint64, len(ss))
	for i, sampSlot := range ss {
		slots[i] = sampSlot.Slot
	}
	return slots
}

func BlocksFromSampleableSlots(ss []SampleableSlot) []*spec.VersionedSignedBeaconBlock {
	blocks := make([]*spec.VersionedSignedBeaconBlock, len(ss))
	for i, sampSlot := range ss {
		blocks[i] = sampSlot.BeaconBlock
	}
	return blocks
}

func WithCustomSlots(slots []uint64) SlotSelector {
	return func(ctx context.Context, g *DasGuardian) ([]SampleableSlot, error) {
		sampSlots := make([]SampleableSlot, len(slots))
		for i, slot := range slots {
			beaconBlock, err := g.apiCli.GetBeaconBlock(ctx, slot)
			if err != nil {
				return sampSlots, fmt.Errorf("retrieving slot %d - %s", slot, err.Error())
			}
			sampBlock := SampleableSlot{
				Slot:        slot,
				BeaconBlock: beaconBlock,
			}
			sampSlots[i] = sampBlock
		}
		return sampSlots, nil
	}
}

func WithDummySlots(slots []uint64) SlotSelector {
	return func(ctx context.Context, g *DasGuardian) ([]SampleableSlot, error) {
		return nil, nil
	}
}

// WithRandomSlots returns a random slot composer.
// Generates n number of random slots between the [min(fulu_fork_slot, last_custody_slot), current_head)
func WithRandomSlots(n int) SlotSelector {
	return func(ctx context.Context, g *DasGuardian) ([]SampleableSlot, error) {
		return GenerateRandomSlots(ctx, g, n)
	}
}

func GenerateRandomSlots(ctx context.Context, g *DasGuardian, n int) ([]SampleableSlot, error) {
	sampSlots := make([]SampleableSlot, n)
	minSampSlot := GetMinSampleableSlot(g)
	headSlot := g.apiCli.GetLatestBlockHeader()
	if headSlot == nil {
		return sampSlots, fmt.Errorf("unable to retrieve the latest block header")
	}

	randomSlots := selectRandomSlotsForRange(
		int64(minSampSlot),
		int64(headSlot.Slot),
		int64(n),
	)

	for i, slot := range randomSlots {
		beaconBlock, err := g.apiCli.GetBeaconBlock(ctx, slot)
		if err != nil {
			return sampSlots, fmt.Errorf("retrieving slot %d - %s", slot, err.Error())
		}
		sampBlock := SampleableSlot{
			Slot:        slot,
			BeaconBlock: beaconBlock,
		}
		sampSlots[i] = sampBlock
	}
	return sampSlots, nil
}

func GetMinSampleableSlot(g *DasGuardian) uint64 {
	// get the fulu fork epoch and translate it to slot
	fuluSlot := EpochToSlot(g.apiCli.GetFuluForkEpoch())

	// get the min-custody value
	minCustodyEpoch, ok := g.apiCli.ReadSpecParameter("MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS")
	if !ok {
		return fuluSlot
	}
	minCustodySlot := EpochToSlot(minCustodyEpoch.(uint64))

	return min(fuluSlot, minCustodySlot)
}

func EpochToSlot(epoch uint64) uint64 {
	return epoch / SLOTS_PER_EPOCH
}
