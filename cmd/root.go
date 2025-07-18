package main

import (
	"context"
	"os"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

var rootConfig = struct {
	Libp2pHost              string
	Libp2pPort              int
	BeaconAPIendpoint       string
	BeaconAPICustomClClient string
	ConnectionRetries       int
	ConnectionTimeout       time.Duration
	InitTimeout             time.Duration
	WaitForFulu             bool
}{
	Libp2pHost:              "127.0.0.1",
	Libp2pPort:              9013,
	BeaconAPIendpoint:       "http://127.0.0.1:5052/",
	BeaconAPICustomClClient: "",
	ConnectionRetries:       3,
	ConnectionTimeout:       30 * time.Second,
	InitTimeout:             30 * time.Second,
	WaitForFulu:             true,
}

var rootCmd = &cli.Command{
	Name:                  "das-guardian",
	Usage:                 "An ethereum DAS custody checker",
	EnableShellCompletion: true,
	Flags:                 rootFlags,
	Commands: []*cli.Command{
		cmdScan,
		cmdMonitor,
	},
}

var rootFlags = []cli.Flag{
	&cli.StringFlag{
		Name:        "libp2p.host",
		Usage:       "IP for the Libp2p host",
		Value:       rootConfig.Libp2pHost,
		Destination: &rootConfig.Libp2pHost,
	},
	&cli.IntFlag{
		Name:        "libp2p.port",
		Usage:       "Port for the libp2p host",
		Value:       rootConfig.Libp2pPort,
		Destination: &rootConfig.Libp2pPort,
	},
	&cli.StringFlag{
		Name:        "api.endpoint",
		Usage:       "The url endpoint of a Beacon API (http://localhost:5052/)",
		Value:       rootConfig.BeaconAPIendpoint,
		Destination: &rootConfig.BeaconAPIendpoint,
	},
	&cli.StringFlag{
		Name:        "api.custom.cl",
		Usage:       "Name of a custom CL client that we would like to query from the work-balancer ('lighthouse', 'prysm', 'nimbus')",
		Value:       rootConfig.BeaconAPICustomClClient,
		Destination: &rootConfig.BeaconAPICustomClClient,
	},
	&cli.IntFlag{
		Name:        "connection.retries",
		Usage:       "Number of retries when connecting the node",
		Value:       rootConfig.ConnectionRetries,
		Destination: &rootConfig.ConnectionRetries,
	},
	&cli.DurationFlag{
		Name:        "connection.timeout",
		Usage:       "Timeout for the connection attempt to the node",
		Value:       rootConfig.ConnectionTimeout,
		Destination: &rootConfig.ConnectionTimeout,
	},
	&cli.DurationFlag{
		Name:        "init.timeout",
		Usage:       "Timeout to limit the time it can take the guardian to init itself",
		Value:       rootConfig.InitTimeout,
		Destination: &rootConfig.InitTimeout,
	},
	&cli.BoolFlag{
		Name:        "wait.fulu",
		Usage:       "The guardian command will wait until fulu hardfork has happened before proceeding to test the custody",
		Value:       rootConfig.WaitForFulu,
		Destination: &rootConfig.WaitForFulu,
	},
}

func main() {
	// Set log level from environment variable
	if level := os.Getenv("LOGRUS_LEVEL"); level != "" {
		if parsedLevel, err := log.ParseLevel(level); err == nil {
			log.SetLevel(parsedLevel)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rootCmd.Run(ctx, os.Args); err != nil && !errors.Is(err, context.Canceled) {
		log.Error(err)
		os.Exit(1)
	}
	os.Exit(0)
}
