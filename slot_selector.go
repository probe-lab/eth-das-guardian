package dasguardian

import (
	"context"
	"fmt"
	mrand "math/rand"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/probe-lab/eth-das-guardian/api"
	"github.com/sirupsen/logrus"
)

const (
	SLOTS_PER_EPOCH = 32
)

type SlotRangeType string

func (s SlotRangeType) String() string { return string(s) }

const (
	NoSlots              SlotRangeType = "none"
	CustomSlots          SlotRangeType = "custom"
	RandomNonMissedSlots SlotRangeType = "random-not-missed"
	RandomWithBlobsSlots SlotRangeType = "random-with-blobs"
	RandomAvailableSlots SlotRangeType = "random-available-slots"
)

func PrintSlotSelectorOptions() string {
	return fmt.Sprintf(
		"[%s, %s, %s, %s, %s]",
		NoSlots.String(),
		CustomSlots.String(),
		RandomNonMissedSlots.String(),
		RandomWithBlobsSlots.String(),
		RandomAvailableSlots.String(),
	)
}

func SlotRangeTypeFromString(s string) SlotRangeType {
	switch s {
	case NoSlots.String():
		return NoSlots
	case CustomSlots.String():
		return CustomSlots
	case RandomNonMissedSlots.String():
		return RandomNonMissedSlots
	case RandomWithBlobsSlots.String():
		return RandomWithBlobsSlots
	case RandomAvailableSlots.String():
		return RandomAvailableSlots
	default:
		return RandomAvailableSlots
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

	case RandomNonMissedSlots, RandomWithBlobsSlots, RandomAvailableSlots:
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
	case RandomNonMissedSlots:
		return WithRandomNonMissedSlots(p.Range)
	case RandomWithBlobsSlots:
		return WithRandomWithBlobsSlots(p.Range)
	case RandomAvailableSlots:
		return WithRandomAvailableSlots(p.Range)
	default:
		return WithRandomAvailableSlots(p.Range)
	}
}

// SlotSelector is tha main option interface to define which kind of slots we want to select
// NOTE: all the slots need to be over the fulu fork, otherwise we can't request DataColums
type SlotSelector func(context.Context, BeaconAPI, *StatusV2) ([]SampleableSlot, error)

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
	return func(ctx context.Context, apiCli BeaconAPI, _ *StatusV2) ([]SampleableSlot, error) {
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
	return func(ctx context.Context, apiCli BeaconAPI, _ *StatusV2) ([]SampleableSlot, error) {
		return nil, nil
	}
}

// WithRandomSlots returns a random slot composer.
// Generates n number of random slots between the [min(fulu_fork_slot, last_custody_slot), current_head)
func WithRandomSlots(n int32) SlotSelector {
	return func(ctx context.Context, apiCli BeaconAPI, status *StatusV2) ([]SampleableSlot, error) {
		// accept any random slot
		valFn := func(b *spec.VersionedSignedBeaconBlock) bool { return true }
		return GenerateRandomSlots(ctx, apiCli, n, valFn, status)
	}
}

type validationFn func(*spec.VersionedSignedBeaconBlock) bool

func GenerateRandomSlots(ctx context.Context, beaconApi BeaconAPI, n int32, valFn validationFn, statusV2 *StatusV2) ([]SampleableSlot, error) {
	if n <= 0 {
		return []SampleableSlot{}, nil
	}

	minSamplSlot, headerSlot, err := GetMinAndHeadSlot(beaconApi, statusV2)
	if err != nil {
		return nil, fmt.Errorf("getting min and head slots - %s", err.Error())
	}
	if headerSlot < minSamplSlot {
		return nil, fmt.Errorf("invalid slot range: headerSlot (%d) < minSamplSlot (%d)", headerSlot, minSamplSlot)
	}
	availableSlots := headerSlot - minSamplSlot + 1
	if availableSlots == 0 {
		return []SampleableSlot{}, nil
	}

	sampSlots := make([]SampleableSlot, 0, n)
	checkedSlots := make(map[uint64]struct{})

	maxIterations := 10 // Prevent infinite loops
	iteration := 0

	// Keep generating random slots until we have n valid ones
	for len(sampSlots) < int(n) && iteration < maxIterations {
		iteration++

		// Calculate how many more slots we need
		needed := int(n) - len(sampSlots)

		// Generate a reasonable batch size (not too large)
		batchSize := uint64(needed * 3) // 3x what we need
		if batchSize > availableSlots {
			batchSize = availableSlots
		}
		if batchSize > 100 { // Cap at reasonable limit
			batchSize = 100
		}

		rawSlots := selectRandomSlotsForRange(minSamplSlot, headerSlot, batchSize)

		validFound := false
		for _, slot := range rawSlots {
			if _, exists := checkedSlots[slot]; exists {
				continue
			}
			checkedSlots[slot] = struct{}{}

			bblock, err := beaconApi.GetBeaconBlock(ctx, slot)
			if err != nil {
				switch err {
				case api.ErrBlockNotFound:
					continue
				default:
					return nil, fmt.Errorf("retrieving slot %d - %v", slot, err)
				}
			}

			if valFn(bblock) {
				sampSlots = append(sampSlots, SampleableSlot{
					Slot:        slot,
					BeaconBlock: bblock,
				})
				validFound = true

				if len(sampSlots) >= int(n) {
					break
				}
			}
		}

		// If we've checked all available slots or found no valid slots in this batch
		if len(checkedSlots) >= int(availableSlots) {
			break
		}

		// If we didn't find any valid slots in this iteration, increase batch size for next iteration
		if !validFound && iteration < maxIterations-1 {
			continue
		}
	}

	logrus.WithFields(logrus.Fields{
		"total-requested": len(checkedSlots),
		"valid-ones":      len(sampSlots),
	}).Debug("generated random slots for sampling")

	return sampSlots, nil
}

func electraNonMissedBlockValidation(b *spec.VersionedSignedBeaconBlock) bool {
	// accept only slots that are not missed
	if b == nil || b.Electra == nil {
		return false
	}
	return b.Electra.Message.Slot > 0
}

func electraNonBlocksWithBlobsValidation(b *spec.VersionedSignedBeaconBlock) bool {
	// accept only slots that are not missed
	if b == nil || b.Electra == nil {
		return false
	}
	if b.Electra.Message.Slot == 0 {
		return false
	}
	return len(b.Electra.Message.Body.BlobKZGCommitments) > 0
}

func WithRandomNonMissedSlots(n int32) SlotSelector {
	return func(ctx context.Context, apiCli BeaconAPI, statusV2 *StatusV2) ([]SampleableSlot, error) {
		return GenerateRandomSlots(ctx, apiCli, n, electraNonMissedBlockValidation, statusV2)
	}
}

func WithRandomWithBlobsSlots(n int32) SlotSelector {
	return func(ctx context.Context, g BeaconAPI, statusV2 *StatusV2) ([]SampleableSlot, error) {
		return GenerateRandomSlots(ctx, g, n, electraNonBlocksWithBlobsValidation, statusV2)
	}
}

func WithRandomAvailableSlots(n int32) SlotSelector {
	return func(ctx context.Context, g BeaconAPI, statusV2 *StatusV2) ([]SampleableSlot, error) {
		return GenerateRandomSlots(ctx, g, n, electraNonBlocksWithBlobsValidation, statusV2)
	}
}

func GetMaxSampleableSlot(fuluSlot, headSlot, custodySlots, earliestAvailableSlot uint64) uint64 {
	if custodySlots >= headSlot {
		custodySlots = headSlot
	}
	lastCustody := headSlot - custodySlots
	return max(fuluSlot, lastCustody, earliestAvailableSlot)
}

func GetMinAndHeadSlot(beaconApi BeaconAPI, statusV2 *StatusV2) (uint64, uint64, error) {
	// First, figure out how many unique slots we can actually get
	// based on the custody fork + head slot:
	header := beaconApi.GetLatestBlockHeader()
	if header == nil {
		return 0, 0, fmt.Errorf("unable to retrieve the latest block header")
	}
	// get the fulu fork epoch and translate it to slot
	fuluSlot := EpochToSlot(beaconApi.GetFuluForkEpoch())
	// get the min-custody value
	custodyEpochs, ok := beaconApi.ReadSpecParameter("MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS")
	if !ok {
		return 0, 0, fmt.Errorf("unable to retrieve the column custody from the specs")
	}
	minSampSlot := GetMaxSampleableSlot(fuluSlot, uint64(header.Slot), EpochToSlot(custodyEpochs.(uint64)), statusV2.EarliestAvailableSlot)
	return minSampSlot, uint64(header.Slot), nil
}

func selectRandomSlotsForRange(minSlot, headSlot, bins uint64) []uint64 {
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
	for uint64(len(randomSlots)) < bins {
		randomSlot := minSlot + uint64(mrand.Int63n(int64(rangeSize)))
		slot := randomSlot

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
