package main

import (
	"context"
	"fmt"

	pubsub "github.com/libp2p/go-libp2p-pubsub"
)

var GossipBeaconBlock = "/eth/%s/beacon_block/ssz_snappy"

func getMandatoryTopics(forkD string) []string {
	return []string{
		fmt.Sprintf(GossipBeaconBlock, forkD),
	}
}

//lint:ignore U1000 ignore this, keeping it just in case!
func dummyHandler(ctx context.Context, msg *pubsub.Message) error {
	prettyLogrusFields("new message", map[string]any{
		"topic": msg.Topic,
		"from":  string(msg.From),
		"bytes": len(msg.Data),
	})
	return nil
}
