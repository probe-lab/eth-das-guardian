package main

import (
	"context"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/pkg/errors"
	dasguardian "github.com/probe-lab/eth-das-guardian"
	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v3"
)

var scanConfig = struct {
	NodeKeys        []string
	ScanConcurrency int32
}{
	NodeKeys:        make([]string, 0),
	ScanConcurrency: int32(4),
}

var cmdScan = &cli.Command{
	Name:                  "scan",
	Usage:                 "Connects and scans a given node for its custody and network status",
	EnableShellCompletion: true,
	Action:                scanAction,
	Flags:                 scanFlags,
}

var scanFlags = []cli.Flag{
	&cli.StringSliceFlag{
		Name:        "scan.key",
		Usage:       "ENR entries of the node we want to probe",
		Value:       scanConfig.NodeKeys,
		Destination: &scanConfig.NodeKeys,
	},
	&cli.Int32Flag{
		Name:        "scan.concurrency",
		Usage:       "Number of concurrent scans that we would like to perform",
		Value:       scanConfig.ScanConcurrency,
		Destination: &scanConfig.ScanConcurrency,
	},
}

func scanAction(ctx context.Context, cmd *cli.Command) error {
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

	switch len(scanConfig.NodeKeys) {
	case 0:
		return errors.New("no ENR keys were given")
	case 1:
		// compose the network target for the peer
		ethNode, err := dasguardian.ParseNode(scanConfig.NodeKeys[0])
		if err != nil {
			return err
		}
		res, err := guardian.Scan(
			ctx,
			ethNode,
		)
		if err != nil {
			return err
		}
		return res.EvalResult.LogVisualization(logger)

	default:
		ethNodes := make([]*enode.Node, len(scanConfig.NodeKeys))
		for i, key := range scanConfig.NodeKeys {
			// compose the network target for the peer
			ethNode, err := dasguardian.ParseNode(key)
			if err != nil {
				return err
			}
			ethNodes[i] = ethNode
		}
		res, err := guardian.ScanMultiple(
			ctx,
			scanConfig.ScanConcurrency,
			ethNodes,
		)
		if err != nil {
			return err
		}
		// TODO: hardcoded visualization
		for _, r := range res {
			err = r.EvalResult.LogVisualization(logger)
			if err != nil {
				log.Error(err)
			}
		}
		return nil
	}
}
