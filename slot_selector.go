package dasguardian

import (
	"context"
	"fmt"
	mrand "math/rand"

	"github.com/attestantio/go-eth2-client/spec"
)

const (
	SLOTS_PER_EPOCH = 32
)

type SlotRangeType string

func (s SlotRangeType) String() string { return string(s) }

const (
	NoSlots              SlotRangeType = "none"
	CustomSlots          SlotRangeType = "custom"
	RandomSlots          SlotRangeType = "random"
	RandomNonMissedSlots SlotRangeType = "random-not-missed"
	RandomWithBlobsSlots SlotRangeType = "random-with-blobs"
)

func SlotRangeTypeFromString(s string) SlotRangeType {
	switch s {
	case NoSlots.String():
		return NoSlots
	case CustomSlots.String():
		return CustomSlots
	case RandomSlots.String():
		return RandomSlots
	case RandomNonMissedSlots.String():
		return RandomNonMissedSlots
	case RandomWithBlobsSlots.String():
		return RandomWithBlobsSlots
	default:
		return RandomSlots // default to Random
	}
}

type SlotRangeRequestParams struct {
	Type  SlotRangeType
	Range int32
	Slots []uint64
}

func (p SlotRangeRequestParams) Validate() error {
	// make the validation per type
	switch p.Type {
	case NoSlots:
		// nothing to check

	case CustomSlots:
		if len(p.Slots) <= 0 {
			return fmt.Errorf("no slots were given")
		}

	case RandomSlots, RandomNonMissedSlots, RandomWithBlobsSlots:
		if p.Range <= 0 {
			return fmt.Errorf("no slot-range was given (%d)", p.Range)
		}

	default:
		return fmt.Errorf("undefined slot-range-type %s", p.Type.String())
	}

	return nil
}

func (p SlotRangeRequestParams) SlotSelector() SlotSelector {
	// make the validation per type
	switch p.Type {
	case NoSlots:
		return WithNoSlots()
	case CustomSlots:
		return WithCustomSlots(p.Slots)
	case RandomSlots:
		return WithRandomSlots(p.Range)
	case RandomNonMissedSlots:
		return WithRandomNonMissedSlots(p.Range)
	case RandomWithBlobsSlots:
		return WithRandomWithBlobsSlots(p.Range)
	default:
		return WithRandomSlots(p.Range)
	}
}

// SlotSelector is the main option interface to define which kind of slots we want to select
// NOTE: all the slots need to be over the fulu fork, otherwise we can't request DataColumns
type SlotSelector func(context.Context, BeaconAPI) ([]SampleableSlot, error)

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
	return func(ctx context.Context, apiCli BeaconAPI) ([]SampleableSlot, error) {
		sampSlots := make([]SampleableSlot, len(slots))
		for i, slot := range slots {
			beaconBlock, err := apiCli.GetBeaconBlock(ctx, slot)
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

func WithNoSlots() SlotSelector {
	return func(ctx context.Context, apiCli BeaconAPI) ([]SampleableSlot, error) {
		return nil, nil
	}
}

// WithRandomSlots returns a random slot composer.
// Generates n number of random slots between the [min(fulu_fork_slot, last_custody_slot), current_head)
func WithRandomSlots(n int32) SlotSelector {
	return func(ctx context.Context, apiCli BeaconAPI) ([]SampleableSlot, error) {
		return GenerateRandomSlots(ctx, apiCli, n)
	}
}

func GenerateRandomSlots(ctx context.Context, apiCli BeaconAPI, n int32) ([]SampleableSlot, error) {
	// First, figure out how many unique slots we can actually get
	// based on the custody fork + head slot:
	header := apiCli.GetLatestBlockHeader()
	if header == nil {
		return nil, fmt.Errorf("unable to retrieve the latest block header")
	}
	// get the fulu fork epoch and translate it to slot
	fuluSlot := EpochToSlot(apiCli.GetFuluForkEpoch())
	// get the min-custody value
	custodyEpochs, ok := apiCli.ReadSpecParameter("MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS")
	if !ok {
		return nil, fmt.Errorf("unable to retrieve the column custody from the specs")
	}
	minSampSlot := GetMaxSampleableSlot(fuluSlot, uint64(header.Slot), EpochToSlot(custodyEpochs.(uint64)))

	// selectRandomSlotsForRange already caps bins to the available range
	rawSlots := selectRandomSlotsForRange(
		int64(minSampSlot),
		int64(header.Slot),
		int64(n),
	)

	// Allocate exactly as many SampleableSlots as we got back
	sampSlots := make([]SampleableSlot, len(rawSlots))
	for i, slot := range rawSlots {
		block, err := apiCli.GetBeaconBlock(ctx, slot)
		if err != nil {
			return nil, fmt.Errorf("retrieving slot %d - %v", slot, err)
		}
		sampSlots[i] = SampleableSlot{
			Slot:        slot,
			BeaconBlock: block,
		}
	}
	return sampSlots, nil
}

func WithRandomNonMissedSlots(n int32) SlotSelector {
	// TODO: update logic to remove missed slots
	return func(ctx context.Context, apiCli BeaconAPI) ([]SampleableSlot, error) {
		return GenerateRandomSlots(ctx, apiCli, n)
	}
}

func WithRandomWithBlobsSlots(n int32) SlotSelector {
	// TODO: update logic to remove missed slots
	return func(ctx context.Context, g BeaconAPI) ([]SampleableSlot, error) {
		return GenerateRandomSlots(ctx, g, n)
	}
}

func GetMaxSampleableSlot(fuluSlot, headSlot, custodySlots uint64) uint64 {
	if custodySlots >= headSlot {
		custodySlots = headSlot
	}
	lastCustody := headSlot - custodySlots
	return max(fuluSlot, lastCustody)
}

func selectRandomSlotsForRange(minSlot int64, headSlot int64, bins int64) []uint64 {
	// Handle edge cases
	if bins <= 0 || minSlot <= 0 || minSlot > headSlot {
		return []uint64{}
	}

	// Calculate the actual available range size
	rangeSize := headSlot - minSlot

	// Ensure we don't request more slots than available
	if bins > rangeSize {
		bins = rangeSize
	}

	// Double check that we have enough slots
	if bins <= 0 {
		return []uint64{}
	}

	// Use a map to ensure uniqueness
	slotSet := make(map[uint64]bool)
	randomSlots := make([]uint64, 0, bins)

	// Generate unique random slots until we have enough to cover bin
	for int64(len(randomSlots)) < bins {
		randomSlot := minSlot + mrand.Int63n(rangeSize)
		slot := uint64(randomSlot)

		if !slotSet[slot] {
			slotSet[slot] = true
			randomSlots = append(randomSlots, slot)
		}
	}

	return randomSlots
}

func EpochToSlot(epoch uint64) uint64 {
	return epoch * SLOTS_PER_EPOCH
}
