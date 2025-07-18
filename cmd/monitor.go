package main

import (
	"context"
	"time"

	"github.com/pkg/errors"
	dasguardian "github.com/probe-lab/eth-das-guardian"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var monitorConfig = struct {
	MonitorFrequency time.Duration
	SlotRangeType    string
	SlotRange        int32
	SlotCustomRange  []uint64
}{
	MonitorFrequency: 1 * time.Minute,
	SlotRangeType:    dasguardian.RandomSlots.String(),
	SlotRange:        int32(5),
	SlotCustomRange:  make([]uint64, 0),
}

var cmdMonitor = &cli.Command{
	Name:                  "monitor",
	Usage:                 "Connects and monitors a given node for its custody and network status",
	EnableShellCompletion: true,
	Action:                monitorAction,
	Flags:                 monitorFlags,
}

var monitorFlags = []cli.Flag{
	&cli.DurationFlag{
		Name:        "freq",
		Usage:       "Intervals at which the node will be monitored",
		Value:       monitorConfig.MonitorFrequency,
		Destination: &monitorConfig.MonitorFrequency,
	},
	&cli.StringFlag{
		Name:        "slot.ramge.type",
		Usage:       "Type of slots that will be queries from the remote node",
		Value:       scanConfig.SlotRangeType,
		Destination: &scanConfig.SlotRangeType,
	},
	&cli.Int32Flag{
		Name:        "slot.range.number",
		Usage:       "Number of slots that will be requested from the remote node",
		Value:       scanConfig.SlotRange,
		Destination: &scanConfig.SlotRange,
	},
	&cli.Uint64SliceFlag{
		Name:        "slot.range.slots",
		Usage:       "Number of concurrent scans that we would like to perform",
		Value:       scanConfig.SlotCustomRange,
		Destination: &scanConfig.SlotCustomRange,
	},
}

func monitorAction(ctx context.Context, cmd *cli.Command) error {
	log.WithFields(log.Fields{
		"beacon-api":         rootConfig.BeaconAPIendpoint,
		"libp2p-host":        rootConfig.Libp2pHost,
		"libp2p-port":        rootConfig.Libp2pPort,
		"connection-retries": rootConfig.ConnectionRetries,
		"connection-timeout": rootConfig.ConnectionTimeout,
		"init-timeout":       rootConfig.InitTimeout,
		"wait-fulu":          rootConfig.WaitForFulu,
		"slot-range-type":    scanConfig.SlotRangeType,
		"slot-range-number":  scanConfig.SlotRange,
		"slot-range-slots":   scanConfig.SlotCustomRange,
	}).Info("running das-guardian")

	logger := log.WithFields(log.Fields{})
	logger.WithFields(log.Fields{
		"freq": monitorConfig.MonitorFrequency,
	}).Info("monitor cmd...")

	ethConfig := &dasguardian.DasGuardianConfig{
		Logger:            logger,
		Libp2pHost:        rootConfig.Libp2pHost,
		Libp2pPort:        rootConfig.Libp2pPort,
		ConnectionRetries: rootConfig.ConnectionRetries,
		ConnectionTimeout: rootConfig.ConnectionTimeout,
		BeaconAPIendpoint: rootConfig.BeaconAPIendpoint,
		WaitForFulu:       rootConfig.WaitForFulu,
		InitTimeout:       rootConfig.InitTimeout,
	}

	guardian, err := dasguardian.NewDASGuardian(ctx, ethConfig)
	if err != nil {
		return err
	}

	// slot range params
	params := dasguardian.SlotRangeRequestParams{
		Type:  dasguardian.SlotRangeTypeFromString(scanConfig.SlotRangeType),
		Range: scanConfig.SlotRange,
		Slots: scanConfig.SlotCustomRange,
	}
	if err := params.Validate(); err != nil {
		return errors.Wrap(err, "validation of the slot-range params")
	}
	slotsSelector := params.SlotSelector()

	log.WithFields(log.Fields{
		"peer-id": guardian.Host().ID().String(),
	}).Info("das-guardian initialized")

	return guardian.MonitorEndpoint(ctx, slotsSelector)
}
