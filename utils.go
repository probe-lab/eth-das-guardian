package dasguardian

import (
	"crypto/elliptic"
	"crypto/sha256"
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

// reverseByteOrder Switch the endianness of a byte slice by reversing its order.
// This function does not modify the actual input bytes.
func reverseByteOrder(input []byte) []byte {
	b := make([]byte, len(input))
	copy(b, input)
	for i := 0; i < len(b)/2; i++ {
		b[i], b[len(b)-i-1] = b[len(b)-i-1], b[i]
	}
	return b
}

func hash(data []byte) [32]byte {
	h := sha256.New()
	h.Reset()

	var b [32]byte

	// The hash interface never returns an error, for that reason
	// we are not handling the error below. For reference, it is
	// stated here https://golang.org/pkg/hash/#Hash

	// #nosec G104
	h.Write(data)
	h.Sum(b[:0])

	return b
}

func isNill(i any) bool {
	return i == nil
}
