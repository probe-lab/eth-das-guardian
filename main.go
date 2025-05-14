package main

import (
	"context"
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"
)

var rootConfig = struct {
	NodeKey           string
	Libp2pHost        string
	Libp2pPort        int
	TrustedPrysm      bool
	PrysmHost         string
	PrysmHTTPport     int
	PrysmGRPCport     int
	ConnectionRetries int
	ConnectionTimeout time.Duration
}{
	NodeKey:           "",
	Libp2pHost:        "127.0.0.1",
	Libp2pPort:        9013,
	TrustedPrysm:      true,
	PrysmHost:         "127.0.0.1",
	PrysmHTTPport:     3500,
	PrysmGRPCport:     4000,
	ConnectionRetries: 3,
	ConnectionTimeout: 30 * time.Second,
}

var app = &cli.Command{
	Name:                  "das-guardian",
	Usage:                 "An ethereum DAS custody checker",
	EnableShellCompletion: true,
	Action:                guardianAction,
	Flags:                 rootFlags,
}

var rootFlags = []cli.Flag{
	&cli.StringFlag{
		Name:        "node-key",
		Usage:       "Node key (ENR or Mulitaddress)",
		Value:       rootConfig.NodeKey,
		Destination: &rootConfig.NodeKey,
	},
	&cli.StringFlag{
		Name:        "libp2p.host",
		Usage:       "IP where Ookla will setup the Libp2p host",
		Value:       rootConfig.Libp2pHost,
		Destination: &rootConfig.Libp2pHost,
	},
	&cli.IntFlag{
		Name:        "libp2p.port",
		Usage:       "Port where Ookla's Libp2p host will listen",
		Value:       rootConfig.Libp2pPort,
		Destination: &rootConfig.Libp2pPort,
	},
	/*
		&cli.BoolFlag{
			Name:        "local.trusted.addr",
			Usage:       "To advertise the localhost multiaddress to our trusted control Prysm node",
			Value:       rootConfig.TrustedPrysm,
			Destination: &rootConfig.TrustedPrysm,
		},
		&cli.StringFlag{
			Name:        "prysm.host",
			Usage:       "The host ip/name where Prysm's (beacon) API is accessible",
			Value:       rootConfig.PrysmHost,
			Destination: &rootConfig.PrysmHost,
		},
		&cli.IntFlag{
			Name:        "prysm.port.http",
			Usage:       "The port on which Prysm's beacon nodes' Query HTTP API is listening on",
			Value:       rootConfig.PrysmHTTPport,
			Destination: &rootConfig.PrysmHTTPport,
		},
		&cli.IntFlag{
			Name:        "prysm.port.grpc",
			Usage:       "The port on which Prysm's gRPC API is listening on",
			Value:       rootConfig.PrysmGRPCport,
			Destination: &rootConfig.PrysmGRPCport,
		},
	*/
	&cli.IntFlag{
		Name:        "connection.retries",
		Usage:       "Number of retries when connecting the node.",
		Value:       rootConfig.ConnectionRetries,
		Destination: &rootConfig.ConnectionRetries,
	},
	&cli.DurationFlag{
		Name:        "connection.timeout",
		Usage:       "Timeout for the connection attempt to the node.",
		Value:       rootConfig.ConnectionTimeout,
		Destination: &rootConfig.ConnectionTimeout,
	},
}

func guardianAction(ctx context.Context, cmd *cli.Command) error {
	log.WithFields(log.Fields{
		"node-key":           truncateStr(rootConfig.NodeKey, 24),
		"libp2p-host":        rootConfig.Libp2pHost,
		"libp2p-port":        rootConfig.Libp2pPort,
		"connection-retries": rootConfig.ConnectionRetries,
		"connection-timeout": rootConfig.ConnectionTimeout,
	}).Info("running eth-das-guardian")

	ethConfig := &DasGuardianConfig{
		Libp2pHost: rootConfig.Libp2pHost,
		Libp2pPort: rootConfig.Libp2pPort,
		ConnectionRetries: rootConfig.ConnectionRetries,
		ConnectionTimeout: rootConfig.ConnectionTimeout,
	}

	guardian, err := NewDASGuardian(ethConfig)
	if err != nil {
		return err
	}

	// compose the network target for the peer
	ethNode, err := parseNode(rootConfig.NodeKey)
	if err != nil {
		return err
	}

	return guardian.Scan(
		ctx,
		ethNode,
	)
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := app.Run(ctx, os.Args); err != nil && !errors.Is(err, context.Canceled) {
		log.Error(err)
		os.Exit(1)
	}
}
