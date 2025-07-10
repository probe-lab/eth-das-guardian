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
	MonitorDuration  time.Duration
}{
	MonitorFrequency: 1 * time.Minute,
	MonitorDuration:  10 * time.Minute,
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
	&cli.DurationFlag{
		Name:        "duration",
		Usage:       "Duration of the whole monitoring process ['5m', '1h']",
		Value:       monitorConfig.MonitorDuration,
		Destination: &monitorConfig.MonitorDuration,
	},
}

func monitorAction(ctx context.Context, cmd *cli.Command) error {
	logger := log.WithFields(log.Fields{})
	logger.WithFields(log.Fields{
		"freq":     monitorConfig.MonitorFrequency,
		"duration": monitorConfig.MonitorDuration,
		"web-mode": rootConfig.WebMode,
		"web-port": rootConfig.WebPort,
	}).Info("monitor cmd...")

	// Start web server in a goroutine if web mode is enabled
	if rootConfig.WebMode {
		go func() {
			log.WithFields(log.Fields{
				"web-port": rootConfig.WebPort,
			}).Info("starting eth-das-guardian web server alongside monitoring")
			dasguardian.StartWebServerWithEndpoint(rootConfig.WebPort, rootConfig.BeaconAPIendpoint, rootConfig.BeaconName)
		}()
	}

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
	return guardian.MonitorEndpoint(ctx)
}
