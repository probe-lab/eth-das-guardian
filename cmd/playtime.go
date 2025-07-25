package main

import (
	"context"

	dasguardian "github.com/probe-lab/eth-das-guardian"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var playTimeConfig = struct {
	Parallelism    int32
	DoraEndpoint   string
	BeaconEndpoint string
	LogDir         string
	DryScan        bool
}{
	Parallelism:    4,
	DoraEndpoint:   "https://dora.fusaka-devnet-2.ethpandaops.io/api/",
	BeaconEndpoint: "https://beacon.fusaka-devnet-2.ethpandaops.io/",
	LogDir:         ".logs",
	DryScan:        true,
}

var cmdPlaytime = &cli.Command{
	Name:  "playtime",
	Usage: "Run monitor or scan commands on all consensus clients from Dora",
	Description: `Fetches all consensus clients from Dora API and runs the specified command
(monitor or scan) on each client in parallel.`,
	Arguments: []cli.Argument{&cli.StringArg{
		Name: "command",
	}},
	Flags: []cli.Flag{
		&cli.Int32Flag{
			Name:        "parallelism",
			Usage:       "Number of parallel executions",
			Value:       playTimeConfig.Parallelism,
			Destination: &playTimeConfig.Parallelism,
		},
		&cli.StringFlag{
			Name:        "dora-endpoint",
			Usage:       "HTTPs endpoint of the dora API",
			Value:       playTimeConfig.DoraEndpoint,
			Destination: &playTimeConfig.DoraEndpoint,
		},
		&cli.StringFlag{
			Name:        "beacon-endpoint",
			Usage:       "HTTPs endpoint of a trusted beacon API",
			Value:       playTimeConfig.BeaconEndpoint,
			Destination: &playTimeConfig.BeaconEndpoint,
		},
		&cli.StringFlag{
			Name:        "log-dir",
			Usage:       "Directory to write log files",
			Value:       playTimeConfig.LogDir,
			Destination: &playTimeConfig.LogDir,
		},
		&cli.BoolFlag{
			Name:        "dry-scan",
			Usage:       "",
			Value:       playTimeConfig.DryScan,
			Destination: &playTimeConfig.DryScan,
		},
	},
	Action: runPlaytime,
}

func runPlaytime(ctx context.Context, cmd *cli.Command) error {
	devnetScanCfg := dasguardian.DevnetScannerConfig{
		LogLevel:          dasguardian.ParseLogLevel(rootConfig.LogLevel),
		LogFormat:         &logrus.JSONFormatter{},
		LogDir:            playTimeConfig.LogDir,
		Parallelism:       playTimeConfig.Parallelism,
		DoraApiEndpoint:   playTimeConfig.DoraEndpoint,
		BeaconApiEndpoint: playTimeConfig.BeaconEndpoint,
		DryScan:           playTimeConfig.DryScan,
	}
	devnetScanner, err := dasguardian.NewDevnetScanner(devnetScanCfg)
	if err != nil {
		return err
	}

	return devnetScanner.Start(ctx)
}
