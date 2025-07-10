package dasguardian

import (
	"fmt"
	mrand "math/rand"

	log "github.com/sirupsen/logrus"
)

func prettyLogrusFields(logger log.FieldLogger, msg string, fields map[string]any) {
	logger.Info(msg)
	for k, v := range fields {
		logger.Info("\t* ", k, ":\t", v)
	}
}

func visualizeRandomSlots(slots []uint64) map[string]any {
	slotInfo := make(map[string]any)
	for i, s := range slots {
		slotInfo[fmt.Sprintf("slot (%d)", i)] = s
	}
	return slotInfo
}

func selectRandomSlotsForRange(headSlot int64, bins int64, maxValue int64) []uint64 {
	if maxValue < bins {
		bins = maxValue
	}

	items := randomItemsForRange(bins, maxValue)
	randomSlots := make([]uint64, len(items))
	for i, it := range items {
		nextTarget := headSlot - it
		// sanity checks
		if nextTarget > headSlot || nextTarget < (headSlot-maxValue) {
			continue
		}
		randomSlots[i] = uint64(nextTarget)
	}
	return randomSlots
}

func randomItemsForRange(bins int64, maxValue int64) []int64 {
	// return a random slot in between the given ranges rand(CUSTODY_SLOTS, HEAD, bins )

	// Handle edge cases
	if bins == 0 || maxValue == 0 {
		return []int64{}
	}

	// Ensure we have at least 1 item per bin
	binSize := maxValue / bins
	if binSize == 0 {
		binSize = 1
	}

	randomSample := func(max, min int64) int64 {
		if max <= min {
			return min
		}
		in := int64(min)
		ax := int64(max)
		return mrand.Int63n(ax-in) + in
	}

	var samples []int64
	for minValue := int64(1); len(samples) < int(bins) && minValue < maxValue; minValue = minValue + binSize {
		maxForBin := minValue + binSize
		if maxForBin > maxValue {
			maxForBin = maxValue
		}
		s := randomSample(maxForBin, minValue)
		samples = append(samples, s)
	}
	return samples
}
