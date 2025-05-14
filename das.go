package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/libp2p/go-libp2p"
	mplex "github.com/libp2p/go-libp2p-mplex"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/tcp"
	ma "github.com/multiformats/go-multiaddr"

	log "github.com/sirupsen/logrus"
)

const (
	// libp2p related metadata
	UserAgent       = "user_agent"
	Protocols       = "protocols"
	Maddrss         = "multiaddresses"
	PeerID          = "peer_id"
	ProtocolVersion = "protocol_version"
	// ethereum beacon status
	ForkDigest     = "fork_digest"
	FinalizedRoot  = "finalized_root"
	FinalizedEpoch = "finalized_epoch"
	HeadRoot       = "head_root"
	HeadSlot       = "head_slot"
	// ethereum beacon metadata
	SeqNumber         = "seq_number"
	Attnets           = "attnets"
	Syncnets          = "syncnets"
	CustodyGroupCount = "custody_group_count"
)

var (
	Libp2pConnGraceTime = 30 * time.Second
)

type DasGuardianConfig struct {
	Libp2pHost string
	Libp2pPort int
	ConnectionRetries int
	ConnectionTimeout time.Duration
}

func (c *DasGuardianConfig) NewPrivateKey() (*crypto.Secp256k1PrivateKey, error) {
	key, err := ecdsa.GenerateKey(gcrypto.S256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	privBytes := gcrypto.FromECDSA(key)
	if len(privBytes) != secp256k1.PrivKeyBytesLen {
		return nil, fmt.Errorf("expected secp256k1 data size to be %d", secp256k1.PrivKeyBytesLen)
	}
	return (*crypto.Secp256k1PrivateKey)(secp256k1.PrivKeyFromBytes(privBytes)), nil
}

func (c *DasGuardianConfig) Libp2pHostOpts() ([]libp2p.Option, error) {
	privKey, err := c.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("get private key: %w", err)
	}

	multiaddr, err := ma.NewMultiaddr(fmt.Sprintf("/ip4/%s/tcp/%d", c.Libp2pHost, c.Libp2pPort))
	if err != nil {
		return nil, fmt.Errorf("construct libp2p listen maddr: %w", err)
	}

	str, err := rcmgr.NewStatsTraceReporter()
	if err != nil {
		return nil, err
	}

	rmgr, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(rcmgr.DefaultLimits.AutoScale()), rcmgr.WithTraceReporter(str))
	if err != nil {
		return nil, err
	}

	opts := []libp2p.Option{
		libp2p.Identity(privKey),
		libp2p.ListenAddrs(multiaddr),
		libp2p.UserAgent("das-guardian"),
		libp2p.Transport(tcp.NewTCPTransport),
		libp2p.Muxer(mplex.ID, mplex.DefaultTransport),
		libp2p.DefaultMuxers,
		libp2p.Security(noise.ID, noise.New),
		libp2p.DisableRelay(),
		libp2p.Ping(false),
		libp2p.ResourceManager(rmgr),
		libp2p.DisableMetrics(),
	}
	return opts, nil
}

type DasGuardian struct {
	cfg *DasGuardianConfig
	host host.Host
}

func NewDASGuardian(cfg *DasGuardianConfig) (*DasGuardian, error) {
	// get the host options from the config
	hostOpts, err := cfg.Libp2pHostOpts()
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(hostOpts...)

	guardian := &DasGuardian{
		cfg: cfg,
		host: h,
	}

	if err := guardian.init(); err != nil {
		return nil, err
	}

	return guardian, nil
}

func (g *DasGuardian) init() error {
	// register the rpc module

	// TODO: Beacon API cli for blob-addressing

	return nil
}

func (g *DasGuardian) Scan(ctx context.Context, ethNode *enode.Node) error {
	// get the info from the ENR
	enodeAddr, err := parseMaddrFromEnode(ethNode)
	if err != nil {
		return err
	}

	custody, err := GetCustodyFromEnr(ethNode)
	if err != nil {
		log.Warn(err.Error())
	}
	custodyGroups := GetCustodyIdxsForNode(ethNode.ID(), int(custody))

	log.WithFields(log.Fields{
		"peer-id":            enodeAddr.ID.String(),
		"maddr":              enodeAddr.Addrs,
		"enr-custody":        custody,
		"enr-custody-groups": custodyGroups,
	}).Info("scanning eth-node...")

	// connection attempt using the libp2p host
	if err := g.ConnectNode(ctx, enodeAddr); err != nil {
		return err
	}

	// extract the necessary information from the ethNode
	metadata := g.GetNodeInfo(enodeAddr.ID)
	log.WithFields(log.Fields(metadata)).Info("successful connection to peer...")

	return nil
}

func (g *DasGuardian) ConnectNode(ctx context.Context, pInfo *peer.AddrInfo) error {
	for r := 1; r <= g.cfg.ConnectionRetries; r++ {
		connCtx, connCancel := context.WithTimeout(ctx, g.cfg.ConnectionTimeout)
		defer connCancel()
		startT := time.Now()
		if err := g.host.Connect(connCtx, *pInfo); err != nil {
			log.Warnf("conn attempt %d failed - %s", r, err.Error())
			select {
			case <- ctx.Done():
				return fmt.Errorf("main context died %s", ctx.Err().Error())
			case <- time.After(Libp2pConnGraceTime - time.Since(startT)):
				continue	
			}
		} else {
			return nil
		}
	} 
	return fmt.Errorf("unreachable node")
}

func (g *DasGuardian) GetNodeInfo(peerID peer.ID) map[string]any {
	metadata := make(map[string]any)

	// libp2p 
	libp2pInfo := g.libp2pPeerInfo(peerID)
	for k, v := range libp2pInfo {
		metadata[k] = v
	}
	// ethereum metadata
	
	// ethreum status

	return metadata
}

func (g *DasGuardian) libp2pPeerInfo(peerID peer.ID) map[string]any {
	libp2pMetadata := make(map[string]any)

	// peer info
	libp2pMetadata[PeerID] = peerID
	maddrss := g.host.Network().Peerstore().PeerInfo(peerID)
	libp2pMetadata[Maddrss] = maddrss.Addrs

	// user agent
	var av any = "unknown"
	av, _ = g.host.Peerstore().Get(peerID, "AgentVersion")
	libp2pMetadata[UserAgent] = av

	// protocols
	prots, _ := g.host.Network().Peerstore().GetProtocols(peerID)
	libp2pMetadata[Protocols] = prots

	// protocol version
	var pv any = "unknown"
	pv, _ = g.host.Peerstore().Get(peerID, "ProtocolVersion")
	libp2pMetadata[ProtocolVersion] = pv
	
	return libp2pMetadata
}

