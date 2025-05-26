package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	mrand "math/rand"
	"time"

	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v6/encoding/bytesutil"
	"github.com/pkg/errors"
	"github.com/probe-lab/eth-das-guardian/rpcs"
	bitfield "github.com/prysmaticlabs/go-bitfield"

	"github.com/probe-lab/eth-das-guardian/api"

	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/encoder"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/libp2p/go-libp2p"
	mplex "github.com/libp2p/go-libp2p-mplex"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
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

	// values
	DataColumnSidecarSubnetCount = uint64(128)
)

const (
	Libp2pConnGraceTime = 30 * time.Second
	InitTimeout         = 10 * time.Second
	ApiStateTimeout     = 30 * time.Second
	ApiQueryTimeout     = 10 * time.Second

	Samples      = uint64(4)
	CustodySlots = uint64(4096 * 16)
)

type DasGuardianConfig struct {
	Libp2pHost        string
	Libp2pPort        int
	ConnectionRetries int
	ConnectionTimeout time.Duration
	BeaconAPIendpoint string
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

	rmgr, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(rcmgr.DefaultLimits.AutoScale()))
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

func (n *DasGuardianConfig) PubsubOptions() []pubsub.Option {
	psOpts := []pubsub.Option{
		pubsub.WithMessageSignaturePolicy(pubsub.StrictNoSign),
		pubsub.WithNoAuthor(),
		pubsub.WithPeerOutboundQueueSize(600),
		pubsub.WithMaxMessageSize(10 * 1 << 20),
		pubsub.WithValidateQueueSize(600),
	}
	return psOpts
}

type DasGuardian struct {
	cfg     *DasGuardianConfig
	host    host.Host
	apiCli  *api.Client
	pubsub  *pubsub.PubSub
	rpcServ *rpcs.ReqResp

	// chain data
	headState    *api.PeerDASstate
	headStatus   pb.Status
	headMetadata pb.MetaDataV2
}

func NewDASGuardian(ctx context.Context, cfg *DasGuardianConfig) (*DasGuardian, error) {
	// get the host options from the config
	hostOpts, err := cfg.Libp2pHostOpts()
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(hostOpts...)
	if err != nil {
		return nil, err
	}

	pubsub, err := pubsub.NewGossipSub(ctx, h, cfg.PubsubOptions()...)
	if err != nil {
		return nil, fmt.Errorf("new PubSub service: %w", err)
	}

	// connect to the Beacon API
	ethApiCfg := api.ClientConfig{
		Endpoint:     cfg.BeaconAPIendpoint,
		StateTimeout: ApiStateTimeout,
		QueryTimeout: ApiQueryTimeout,
	}
	apiCli, err := api.NewClient(ethApiCfg)
	if err != nil {
		return nil, err
	}

	guardian := &DasGuardian{
		cfg:    cfg,
		host:   h,
		pubsub: pubsub,
		apiCli: apiCli,
	}

	initCtx, initCancel := context.WithTimeout(ctx, InitTimeout)
	defer initCancel()
	if err := guardian.init(initCtx); err != nil {
		return nil, err
	}

	return guardian, nil
}

func (g *DasGuardian) init(ctx context.Context) error {
	// check api connection
	if err := g.apiCli.CheckConnection(ctx); err != nil {
		return fmt.Errorf("connection to %s was stablished, but not active - %s", g.cfg.BeaconAPIendpoint, err.Error())
	}

	log.Info("connected to the beacon API...")
	// compose and get the local Metadata
	currentState, err := g.apiCli.GetPeerDASstate(ctx)
	if err != nil {
		return err
	}
	prettyLogrusFields("dowloaded beacon head-state", map[string]any{
		"version":       currentState.Version,
		"finalized":     currentState.Finalized,
		"optimistic-el": currentState.ExecutionOptimistic,
		"validators":    len(currentState.Data.Validators),
	})

	status, err := g.composeLocalBeaconStatus(&currentState)
	if err != nil {
		return err
	}
	prettyLogrusFields("local beacon-status", map[string]any{
		"head-slot":   status.HeadSlot,
		"fork-digest": fmt.Sprintf("0x%x", status.ForkDigest),
	})
	g.headState = &currentState
	g.headStatus = status
	g.headMetadata = g.composeLocalBeaconMetadata()

	// subscribe to main topics
	if err = g.subscribeToTopics(ctx, getMandatoryTopics(currentState.Data.Fork.String())); err != nil {
		return err
	}

	// register the rpc module
	reqRespCfg := &rpcs.ReqRespConfig{
		Encoder:        &encoder.SszNetworkEncoder{},
		ReadTimeout:    g.cfg.ConnectionTimeout,
		WriteTimeout:   g.cfg.ConnectionTimeout,
		BeaconStatus:   g.headStatus,
		BeaconMetadata: g.headMetadata,
	}
	reqResp, err := rpcs.NewReqResp(g.host, reqRespCfg)
	if err != nil {
		return err
	}
	if err := reqResp.RegisterHandlers(ctx); err != nil {
		return err
	}
	g.rpcServ = reqResp

	return nil
}

func (g *DasGuardian) Scan(ctx context.Context, ethNode *enode.Node) error {
	// get the info from the ENR
	enodeAddr, err := parseMaddrFromEnode(ethNode)
	if err != nil {
		return err
	}

	enrCustody, err := GetCustodyFromEnr(ethNode)
	if err != nil {
		log.Warn(err.Error())
	}
	enrCustodyGroups, err := CustodyColumnsSlice(ethNode.ID(), enrCustody, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
	if err != nil {
		return err
	}

	// connection attempt using the libp2p host
	if err := g.ConnectNode(ctx, enodeAddr); err != nil {
		return err
	}

	// extract the necessary information from the ethNode
	libp2pInfo := g.libp2pPeerInfo(enodeAddr.ID)

	// exchange beacon-status
	remoteStatus := g.requestBeaconStatus(ctx, enodeAddr.ID)
	statusLogs := g.visualizeBeaconStatus(remoteStatus)

	// exchange beacon-metadata
	remoteMetadata := g.requestBeaconMetadata(ctx, enodeAddr.ID)
	metadataLogs := g.visualizeBeaconMetadata(remoteMetadata)
	metadataCustodyIdxs, err := CustodyColumnsSlice(ethNode.ID(), remoteMetadata.CustodyGroupCount, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
	if err != nil {
		return errors.Wrap(err, "wrong cuystody subnet")
	}

	// exchange ping
	startT := time.Now()
	if err := g.rpcServ.Ping(ctx, enodeAddr.ID); err != nil {
		return nil
	}
	libp2pInfo["ping_rtt"] = time.Since(startT)

	// compare enr custody to metadata one
	if enrCustody != remoteMetadata.CustodyGroupCount {
		log.Warn("enr custody (%d) mismatches metadata RPC one (%d)", enrCustody, remoteMetadata.CustodyGroupCount)
	}

	prettyLogrusFields("scanning eth-node...", map[string]any{
		"peer-id":            enodeAddr.ID.String(),
		"maddr":              enodeAddr.Addrs,
		"enr-custody":        enrCustody,
		"enr-custody-groups": enrCustodyGroups,
	})
	prettyLogrusFields("libp2p info...", libp2pInfo)
	prettyLogrusFields("beacon status...", statusLogs)
	prettyLogrusFields("beacon metadata...", metadataLogs)

	// select the random slots to sample
	randomSlots := g.selectRandomSlotsForRange(
		uint64(remoteStatus.HeadSlot),
		Samples,
		CustodySlots,
	)
	randomSlotsLogs := g.visualizeRandomSlots(randomSlots)
	prettyLogrusFields("to request slot->blobs ...", randomSlotsLogs)

	// get the blocks so that we can compare the obtained results with the chain ones
	bBlocks, err := g.fetchSlotBlocks(ctx, randomSlots)
	if err != nil {
		return err
	}

	// DAS??!?
	dataCols, err := g.getDataColumnForSlotAndSubnet(ctx, enodeAddr.ID, randomSlots, metadataCustodyIdxs[:])
	if err != nil {
		return err
	}

	// evaluate the results
	return evaluateColumnResponses(randomSlots, metadataCustodyIdxs, bBlocks, dataCols)
}

func (g *DasGuardian) subscribeToTopics(ctx context.Context, topics []string) error {
	for _, topic := range topics {
		t, err := g.pubsub.Join(topic)
		if err != nil {
			return fmt.Errorf("join pubsub topic %s: %w", t, err)
		}
	}
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
			case <-ctx.Done():
				return fmt.Errorf("main context died %s", ctx.Err().Error())
			case <-time.After(Libp2pConnGraceTime - time.Since(startT)):
				continue
			}
		} else {
			return nil
		}
	}
	return fmt.Errorf("unreachable node")
}

func (g *DasGuardian) libp2pPeerInfo(pid peer.ID) map[string]any {
	libp2pMetadata := make(map[string]any)

	// peer info
	libp2pMetadata[PeerID] = pid
	maddrss := g.host.Network().Peerstore().PeerInfo(pid)
	libp2pMetadata[Maddrss] = maddrss.Addrs

	// user agent
	var av any = "unknown"
	av, _ = g.host.Peerstore().Get(pid, "AgentVersion")
	libp2pMetadata[UserAgent] = av

	// protocols
	prots, _ := g.host.Network().Peerstore().GetProtocols(pid)
	libp2pMetadata[Protocols] = prots

	// protocol version
	var pv any = "unknown"
	pv, _ = g.host.Peerstore().Get(pid, "ProtocolVersion")
	libp2pMetadata[ProtocolVersion] = pv

	return libp2pMetadata
}

func (g *DasGuardian) visualizeBeaconStatus(status *pb.Status) map[string]any {
	statusInfo := make(map[string]any)
	if status != nil {
		statusInfo[ForkDigest] = fmt.Sprintf("0x%x", status.ForkDigest)
		statusInfo[FinalizedEpoch] = status.FinalizedEpoch
		statusInfo[FinalizedRoot] = fmt.Sprintf("0x%x", status.FinalizedRoot)
		statusInfo[HeadRoot] = fmt.Sprintf("0x%x", status.HeadRoot)
		statusInfo[HeadSlot] = status.HeadSlot
	} else {
		statusInfo["beacon-status"] = "errored"
	}
	return statusInfo
}

func (g *DasGuardian) requestBeaconStatus(ctx context.Context, pid peer.ID) *pb.Status {
	status, err := g.rpcServ.Status(ctx, pid)
	if err != nil {
		log.Warnf("error requesting beacon-status - %s", err.Error())
	}
	return status
}

func (g *DasGuardian) visualizeBeaconMetadata(metadata *pb.MetaDataV2) map[string]any {
	metadataInfo := make(map[string]any)
	if metadata != nil {
		metadataInfo[SeqNumber] = metadata.SeqNumber
		metadataInfo[Attnets] = fmt.Sprintf("0x%x", metadata.Attnets.Bytes())
		metadataInfo[Syncnets] = fmt.Sprintf("0x%x", metadata.Syncnets.Bytes())
		metadataInfo[CustodyGroupCount] = metadata.CustodyGroupCount
	} else {
		metadataInfo["beacon-metadata"] = "errored"
	}
	return metadataInfo
}

func (g *DasGuardian) requestBeaconMetadata(ctx context.Context, pid peer.ID) *pb.MetaDataV2 {
	metadata, err := g.rpcServ.MetaDataV2(ctx, pid)
	if err != nil {
		log.Warnf("error requesting beacon-metadata - %s", err.Error())
	}
	return metadata
}

func (g *DasGuardian) composeLocalBeaconStatus(state *api.PeerDASstate) (pb.Status, error) {
	// fork digest
	forkDigest, err := computeForkDigest(
		state.Data.Fork.CurrentVersion[:],
		state.Data.GenesisValidatorsRoot[:],
	)
	if err != nil {
		return pb.Status{}, err
	}

	// finalized
	finalizedRoot := bytesutil.ToBytes32(state.Data.FinalizedCheckpoint.Root[:])
	finalizedEpoch := primitives.Epoch(state.Data.FinalizedCheckpoint.Epoch)

	// head
	headRoot := bytesutil.ToBytes32(state.Data.LatestBlockHeader.StateRoot[:])
	headSlot := primitives.Slot(state.Data.LatestBlockHeader.Slot)

	return pb.Status{
		ForkDigest:     forkDigest,
		FinalizedRoot:  finalizedRoot[:],
		FinalizedEpoch: finalizedEpoch,
		HeadRoot:       headRoot[:],
		HeadSlot:       headSlot,
	}, nil
}

func (g *DasGuardian) composeLocalBeaconMetadata() pb.MetaDataV2 {
	return pb.MetaDataV2{
		SeqNumber:         0,
		Attnets:           bitfield.NewBitvector64(),
		Syncnets:          bitfield.Bitvector4{byte(0x00)},
		CustodyGroupCount: uint64(0),
	}
}

func computeForkDigest(forkV []byte, valRoots []byte) ([]byte, error) {
	r, err := (&pb.ForkData{
		CurrentVersion:        forkV,
		GenesisValidatorsRoot: valRoots,
	}).HashTreeRoot()
	if err != nil {
		return []byte{}, err
	}
	digest := bytesutil.ToBytes4(r[:])
	return digest[:], nil
}

func prettyLogrusFields(msg string, fields map[string]any) {
	log.Info(msg)
	for k, v := range fields {
		log.Info("\t* ", k, ":\t", v)
	}
}

func (g *DasGuardian) visualizeRandomSlots(slots []uint64) map[string]any {
	slotInfo := make(map[string]any)
	for i, s := range slots {
		slotInfo[fmt.Sprintf("slot (%d)", i)] = s
	}
	return slotInfo
}

func (g *DasGuardian) selectRandomSlotsForRange(headSlot uint64, bins uint64, maxValue uint64) []uint64 {
	if headSlot < maxValue {
		maxValue = headSlot
	}

	items := g.randomItemsForRange(bins, maxValue)
	randomSlots := make([]uint64, len(items))
	for i, it := range items {
		nextTarget := headSlot - it
		if nextTarget > headSlot || nextTarget < (headSlot-CustodySlots) {
			continue
		}
		randomSlots[i] = nextTarget
	}
	return randomSlots
}

func (g *DasGuardian) randomItemsForRange(bins uint64, maxValue uint64) []uint64 {
	// return a random slot in between the given ranges rand(CUSTODY_SLOTS, HEAD, bins )
	binSize := maxValue / bins
	randomSample := func(max, min uint64) uint64 {
		in := int64(min)
		ax := int64(max)
		return uint64(mrand.Int63n(ax-in) + in)
	}
	var samples []uint64
	for minValue := uint64(1); len(samples) < int(bins); minValue = minValue + binSize {
		s := randomSample(minValue+binSize, minValue)
		samples = append(samples, s)
	}
	return samples
}

func (g *DasGuardian) getDataColumnForSlotAndSubnet(ctx context.Context, pid peer.ID, slots []uint64, columnIdxs []uint64) ([][]*pb.DataColumnSidecar, error) {
	log.WithFields(log.Fields{
		"slots":   len(slots),
		"columns": len(columnIdxs),
	}).Info("sampling node for...")

	// TODO: make sure that we limit the number of columns that we request (slots * idxs * columns)
	dataColumns := make([][]*pb.DataColumnSidecar, len(slots))

	startT := time.Now()
	// make the request for each slots
	for s, slot := range slots {
		// make the request per each column
		duration, cols, err := g.rpcServ.DataColumnByRangeV1(ctx, pid, slot, columnIdxs)
		if err != nil {
			return dataColumns, err
		}
		dataColumns[s] = cols

		// compose the results
		log.WithFields(log.Fields{
			"req-duration": duration,
			"slot":         slot,
			"das-result":   fmt.Sprintf("%d/%d columns", len(cols), len(columnIdxs)),
		}).Info("req info...")
	}

	opDur := time.Since(startT)
	log.WithFields(log.Fields{
		"duration": opDur,
	}).Info("node custody sampling done...")
	return dataColumns, nil
}

func (g *DasGuardian) fetchSlotBlocks(ctx context.Context, slots []uint64) ([]api.BeaconBlock, error) {
	log.WithFields(log.Fields{
		"slots": slots,
	}).Info("requesting slot-blocks from beacon API...")
	blocks := make([]api.BeaconBlock, len(slots))
	for i, slot := range slots {
		b, err := g.apiCli.GetBeaconBlock(ctx, slot)
		if err != nil {
			return blocks, err
		}
		blocks[i] = b
	}
	return blocks, nil
}
