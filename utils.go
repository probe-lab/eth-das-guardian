package dasguardian

import (
	"crypto/elliptic"
	"fmt"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

func ParseNode(rawEnr string) (*enode.Node, error) {
	// check first if the key is a ENR
	return enode.Parse(enode.ValidSchemes, rawEnr)
}

func ParseMaddrFromEnode(ethNode *enode.Node) (*peer.AddrInfo, error) {
	// TODO: only working with IPv4 for now
	ipv4 := ethNode.IP()
	port := ethNode.TCP()
	peerID, err := libp2pPeerIDfromNodeID(ethNode)
	if err != nil {
		return nil, err
	}

	maddr, err := ma.NewMultiaddr(
		fmt.Sprintf(
			"/ip4/%s/tcp/%d",
			ipv4,
			port,
		),
	)
	return &peer.AddrInfo{
		ID:    *peerID,
		Addrs: []ma.Multiaddr{maddr},
	}, err
}

func libp2pPeerIDfromNodeID(ethNode *enode.Node) (*peer.ID, error) {
	pubKey := ethNode.Pubkey()
	if pubKey == nil {
		return nil, fmt.Errorf("no public key")
	}

	// tried to move away from the "Deprecated elliptic" dependency
	// but the suggested pubKey.EDCH() method fails and it still calls elliptic.Marshal
	// https://cs.opensource.google/go/go/+/refs/tags/go1.24.3:src/crypto/ecdsa/ecdsa.go;l=59
	//lint:ignore SA1019 ignore this, not that easy to find a work around!
	pubBytes := elliptic.Marshal(pubKey.Curve, pubKey.X, pubKey.Y)
	secpKey, err := crypto.UnmarshalSecp256k1PublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal secp256k1 public key: %w", err)
	}

	peerID, err := peer.IDFromPublicKey(secpKey)
	if err != nil {
		return nil, fmt.Errorf("peer ID from public key: %w", err)
	}
	return &peerID, nil
}

func truncateStr(text string, width int) string {
	r := []rune(text)
	trunc := r[:width]
	return string(trunc) + "..."
}
