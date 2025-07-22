package dasguardian

import (
	"fmt"

	log "github.com/sirupsen/logrus"
)

func prettyLogrusFields(logger log.FieldLogger, msg string, fields map[string]any) {
	logger.Info(msg)
	for k, v := range fields {
		logger.Info("\t* ", k, ":\t", v)
	}
}

func visualizeRandomSlots(slots []SampleableSlot) map[string]any {
	slotInfo := make(map[string]any)
	for i, s := range slots {
		slotInfo[fmt.Sprintf("slot (%d)", i)] = s.Slot
	}
	return slotInfo
}
