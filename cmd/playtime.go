package main

import (
	"context"
	"time"

	dasguardian "github.com/probe-lab/eth-das-guardian"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var playTimeConfig = struct {
	Parallelism             int32
	DoraEndpoint            string
	BeaconEndpoint          string
	LogDir                  string
	ScanFreq                time.Duration
	DryScan                 bool
	FilterClientsContaining string
}{
	Parallelism:             4,
	DoraEndpoint:            "https://dora.fusaka-devnet-3.ethpandaops.io/api/",
	BeaconEndpoint:          "https://beacon.fusaka-devnet-3.ethpandaops.io/",
	LogDir:                  ".logs",
	ScanFreq:                30 * time.Second,
	DryScan:                 false,
	FilterClientsContaining: "",
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
		&cli.DurationFlag{
			Name:        "scan-freq",
			Usage:       "Time interval between each of the playtime scan tries",
			Value:       playTimeConfig.ScanFreq,
			Destination: &playTimeConfig.ScanFreq,
		},
		&cli.BoolFlag{
			Name:        "dry-scan",
			Usage:       "Performs a single scan of the network",
			Value:       playTimeConfig.DryScan,
			Destination: &playTimeConfig.DryScan,
		},
		&cli.StringFlag{
			Name:        "filter-clients-with",
			Usage:       "Substring that will be used to filter only those clients that include it in their Dora name",
			Value:       playTimeConfig.FilterClientsContaining,
			Destination: &playTimeConfig.FilterClientsContaining,
		},
	},
	Action: runPlaytime,
}

func runPlaytime(ctx context.Context, cmd *cli.Command) error {
	devnetScanCfg := dasguardian.DevnetScannerConfig{
		LogLevel:                dasguardian.ParseLogLevel(rootConfig.LogLevel),
		LogFormat:               &logrus.JSONFormatter{},
		LogDir:                  playTimeConfig.LogDir,
		Parallelism:             playTimeConfig.Parallelism,
		DoraApiEndpoint:         playTimeConfig.DoraEndpoint,
		BeaconApiEndpoint:       playTimeConfig.BeaconEndpoint,
		ScanFreq:                playTimeConfig.ScanFreq,
		DryScan:                 playTimeConfig.DryScan,
		FilterClientsContaining: playTimeConfig.FilterClientsContaining,
	}
	devnetScanner, err := dasguardian.NewDevnetScanner(devnetScanCfg)
	if err != nil {
		return err
	}

	return devnetScanner.Start(ctx)
}
