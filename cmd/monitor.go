package main

import (
	"context"
	"time"

	dasguardian "github.com/probe-lab/eth-das-guardian"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var monitorConfig = struct {
	MonitorFrequency time.Duration
}{
	MonitorFrequency: 1 * time.Minute,
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

	log.WithFields(log.Fields{
		"peer-id": guardian.Host().ID().String(),
	}).Info("das-guardian initialized")

	return guardian.MonitorEndpoint(ctx)
}
