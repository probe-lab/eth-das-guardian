package dasguardian

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/pkg/errors"
	"github.com/probe-lab/eth-das-guardian/api"
	"github.com/wealdtech/go-bytesutil"

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
	Libp2pConnGraceTime = 30 * time.Second

	Samples      = uint64(4)         // TODO: hardcoded
	CustodySlots = uint64(4096 * 32) // default custody in the fulu specs
)

const (
	// libp2p related metadata
	UserAgent       = "user_agent"
	Protocols       = "protocols"
	Maddrss         = "multiaddresses"
	PeerID          = "peer_id"
	ProtocolVersion = "protocol_version"
	ENR             = "enr"
	// ethereum beacon status
	ForkDigest            = "fork_digest"
	FinalizedRoot         = "finalized_root"
	FinalizedEpoch        = "finalized_epoch"
	HeadRoot              = "head_root"
	HeadSlot              = "head_slot"
	EarliestAvailableSlot = "earliest_available_slot"
	// ethereum beacon metadata
	SeqNumber         = "seq_number"
	Attnets           = "attnets"
	Syncnets          = "syncnets"
	CustodyGroupCount = "custody_group_count"
	StatusVersion     = "status_version"
	MetadataVersion   = "metadata_version"
	// values
	DataColumnSidecarSubnetCount = uint64(128)
)

type DasGuardianConfig struct {
	Logger            log.FieldLogger
	Libp2pHost        string
	Libp2pPort        int
	ConnectionRetries int
	ConnectionTimeout time.Duration
	BeaconAPI         BeaconAPI
	BeaconAPIendpoint string
	WaitForFulu       bool
	InitTimeout       time.Duration
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
	// configurations
	cfg *DasGuardianConfig

	// services
	host      host.Host
	beaconApi BeaconAPI
	pubsub    *pubsub.PubSub
	rpcServ   *ReqResp

	nodeIdentity *api.NodeIdentity
	localchain   ChainData
}

type ChainData struct {
	*StatusV1
	*MetaDataV2
	*StatusV2
	*MetaDataV3
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

	sub, err := h.EventBus().Subscribe(event.WildcardSubscription)
	if err != nil {
		return nil, fmt.Errorf("failed to start wildcard eventbus subscription: %w", err)
	}

	go func() {
		defer sub.Close()
		for {
			select {
			case evt := <-sub.Out():
				cfg.Logger.WithField("event", fmt.Sprintf("%T%+v", evt, evt)).Info("received eventbus event")
			case <-ctx.Done():
				return
			}
		}
	}()

	pubsub, err := pubsub.NewGossipSub(ctx, h, cfg.PubsubOptions()...)
	if err != nil {
		return nil, fmt.Errorf("new PubSub service: %w", err)
	}

	// connect to the Beacon API
	var beaconApi BeaconAPI
	switch {
	case cfg.BeaconAPI != nil:
		beaconApi = cfg.BeaconAPI
	case cfg.BeaconAPIendpoint != "":
		beaconApi, err = NewBeaconAPI(BeaconAPIConfig{
			Logger:      cfg.Logger,
			Endpoint:    cfg.BeaconAPIendpoint,
			WaitForFulu: cfg.WaitForFulu,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("no beacon API configured")
	}

	guardian := &DasGuardian{
		cfg:       cfg,
		host:      h,
		pubsub:    pubsub,
		beaconApi: beaconApi,
	}

	initCtx, initCancel := context.WithTimeout(ctx, cfg.InitTimeout)
	defer initCancel()
	if err := guardian.init(initCtx); err != nil {
		return nil, err
	}

	return guardian, nil
}

func (g *DasGuardian) Host() host.Host {
	return g.host
}

func (g *DasGuardian) init(ctx context.Context) error {
	// init beacon-api
	if err := g.beaconApi.Init(ctx); err != nil {
		return err
	}

	// get the information directly from the Beacon API
	nodeIdentity, err := g.beaconApi.GetNodeIdentity(ctx)
	if err != nil {
		return err
	}
	g.nodeIdentity = nodeIdentity

	statusV1, statusV2, err := g.composeLocalBeaconStatus()
	if err != nil {
		return err
	}
	prettyLogrusFields(g.cfg.Logger, "local beacon-status", map[string]any{
		"head-slot":   statusV1.HeadSlot,
		"fork-digest": fmt.Sprintf("0x%x", statusV1.ForkDigest),
	})

	metadataV2, metadataV3 := g.composeLocalBeaconMetadata()
	prettyLogrusFields(g.cfg.Logger, "local beacon-metadata", map[string]any{
		"seq-number": metadataV2.SeqNumber,
		"attnets":    metadataV2.Attnets,
		"syncnets":   metadataV2.Syncnets,
	})

	g.localchain = ChainData{
		StatusV1:   statusV1,
		StatusV2:   statusV2,
		MetaDataV2: metadataV2,
		MetaDataV3: metadataV3,
	}

	// subscribe to main topics
	forkDigest, err := g.beaconApi.GetForkDigest(statusV2.HeadSlot)
	if err != nil {
		return err
	}
	if err = g.subscribeToTopics(ctx, getMandatoryTopics(forkDigest)); err != nil {
		return err
	}

	// register the rpc module
	reqRespCfg := &ReqRespConfig{
		Logger:       g.cfg.Logger,
		ReadTimeout:  g.cfg.ConnectionTimeout,
		WriteTimeout: g.cfg.ConnectionTimeout,
		ForkDigestFn: func(slot uint64) []byte {
			digest, _ := g.beaconApi.GetForkDigest(slot)
			return digest
		},
		ChainData: g.localchain,
	}
	reqResp, err := NewReqResp(g.host, reqRespCfg)
	if err != nil {
		return err
	}
	if err := reqResp.RegisterHandlers(ctx); err != nil {
		return err
	}
	g.rpcServ = reqResp

	return nil
}

type DasGuardianScanResult struct {
	Libp2pInfo       map[string]any
	RemoteStatusV1   *StatusV1
	RemoteStatusV2   *StatusV2
	RemoteMetadataV2 *MetaDataV2
	RemoteMetadataV3 *MetaDataV3
	EvalResult       DASEvaluationResult
}

func (g *DasGuardian) Scan(ctx context.Context, ethNode *enode.Node) (*DasGuardianScanResult, error) {
	return g.scan(ctx, ethNode)
}

func (g *DasGuardian) ScanMultiple(ctx context.Context, concurrency int32, ethNodes []*enode.Node) ([]*DasGuardianScanResult, error) {
	dasResults := make([]*DasGuardianScanResult, 0, len(ethNodes))
	scanC := make(chan *enode.Node, concurrency)
	resultC := make(chan *DasGuardianScanResult)

	closeScan := make(chan struct{})
	closeResult := make(chan struct{})

	var scanWG sync.WaitGroup
	var resWG sync.WaitGroup
	worker := func() {
		defer scanWG.Done()

		select {
		case <-ctx.Done():
			return

		case ethNode := <-scanC:
			res, err := g.scan(ctx, ethNode)
			if err != nil {
				g.cfg.Logger.WithField("node_id", ethNode.ID().String()).Error("")
			}
			res.EvalResult.Error = err
			resultC <- res
		case <-closeScan:
			return
		}
	}

	resCollector := func() {
		defer resWG.Done()
		select {
		case res, ok := <-resultC:
			if !ok {
				break
			}
			dasResults = append(dasResults, res)
		case <-ctx.Done():
			break
		case <-closeResult:
			break
		}
	}

	resWG.Add(1)
	go resCollector()
	for w := int32(0); w < concurrency; w++ {
		scanWG.Add(1)
		go worker()
	}

	for _, node := range ethNodes {
		scanC <- node
	}
	// close the scan workers
	close(closeScan)
	scanWG.Wait()
	// close the result collector
	close(closeResult)
	resWG.Wait()
	return dasResults, nil
}

type PeerInfo struct {
	AddrInfo   *peer.AddrInfo
	Enode      *enode.Node
	Libp2pInfo Libp2pInfo
}

func (g *DasGuardian) scan(ctx context.Context, enode *enode.Node) (*DasGuardianScanResult, error) {
	// get the info from the ENR
	addrinfo, err := ParseMaddrFromEnode(enode)
	if err != nil {
		return nil, err
	}

	peerInfo, err := g.ConnectNode(ctx, addrinfo, enode)
	if err != nil {
		return nil, err
	}

	switch g.beaconApi.GetStateVersion() {
	case "electra":
		return g.scanElectra(ctx, peerInfo)
	case "fulu":
		return g.scanFulu(ctx, peerInfo)
	default:
		return nil, fmt.Errorf("not recognized fork for the state %s", g.beaconApi.GetStateVersion())
	}
}

func (g *DasGuardian) scanElectra(ctx context.Context, peer *PeerInfo) (*DasGuardianScanResult, error) {
	scanResult := &DasGuardianScanResult{
		Libp2pInfo: peer.Libp2pInfo,
	}

	// exchange beacon-status
	remoteStatus := g.requestBeaconStatusV1(ctx, peer.AddrInfo.ID)
	if remoteStatus == nil {
		return scanResult, fmt.Errorf("failed to get beacon status from peer %s", peer.Enode.ID())
	}
	scanResult.RemoteStatusV1 = remoteStatus
	statusLogs := g.visualizeBeaconStatusV1(remoteStatus)

	// exchange beacon-metadata
	remoteMetadata := g.requestBeaconMetadataV2(ctx, peer.AddrInfo.ID)
	if remoteMetadata == nil {
		return scanResult, fmt.Errorf("failed to get beacon metadata from peer %s", peer.Enode.ID())
	}

	scanResult.RemoteMetadataV2 = remoteMetadata
	metadataLogs := g.visualizeBeaconMetadataV2(remoteMetadata)

	prettyLogrusFields(g.cfg.Logger, "scanning eth-node...", map[string]any{
		"peer-id": peer.AddrInfo.ID.String(),
		"maddr":   peer.AddrInfo.Addrs,
	})
	prettyLogrusFields(g.cfg.Logger, "beacon status...", statusLogs)
	prettyLogrusFields(g.cfg.Logger, "beacon metadata...", metadataLogs)

	return scanResult, nil
}

func (g *DasGuardian) scanFulu(ctx context.Context, peerInfo *PeerInfo) (*DasGuardianScanResult, error) {
	scanResult := &DasGuardianScanResult{
		Libp2pInfo: peerInfo.Libp2pInfo,
	}

	// exchange beacon-status
	remoteStatus := g.requestBeaconStatusV2(ctx, peerInfo.AddrInfo.ID)
	if remoteStatus == nil {
		return scanResult, fmt.Errorf("failed to get beacon status from peer %s", peerInfo.Enode.ID())
	}
	scanResult.RemoteStatusV2 = remoteStatus
	statusLogs := g.visualizeBeaconStatusV2(remoteStatus)

	// exchange beacon-metadata
	remoteMetadata := g.requestBeaconMetadataV3(ctx, peerInfo.AddrInfo.ID)
	if remoteMetadata == nil {
		return scanResult, fmt.Errorf("failed to get beacon metadata from peer %s", peerInfo.Enode.ID())
	}

	scanResult.RemoteMetadataV3 = remoteMetadata
	metadataLogs := g.visualizeBeaconMetadataV3(remoteMetadata)
	metadataCustodyIdxs, err := CustodyColumnsSlice(peerInfo.Enode.ID(), remoteMetadata.CustodyGroupCount, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
	if err != nil {
		return scanResult, errors.Wrap(err, "wrong cuystody subnet")
	}

	enrCustody, err := GetCustodyFromEnr(peerInfo.Enode)
	if err != nil {
		g.cfg.Logger.Warn(err.Error())
	}
	enrCustodyGroups, err := CustodyColumnsSlice(peerInfo.Enode.ID(), enrCustody, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
	if err != nil {
		return nil, err
	}

	// compare enr custody to metadata one
	if enrCustody != remoteMetadata.CustodyGroupCount {
		g.cfg.Logger.Warnf("enr custody (%d) mismatches metadata RPC one (%d)", enrCustody, remoteMetadata.CustodyGroupCount)
	}

	prettyLogrusFields(g.cfg.Logger, "scanning eth-node...", map[string]any{
		"peer-id":            peerInfo.AddrInfo.ID.String(),
		"maddr":              peerInfo.AddrInfo.Addrs,
		"enr-custody":        enrCustody,
		"enr-custody-groups": enrCustodyGroups,
	})
	prettyLogrusFields(g.cfg.Logger, "beacon status...", statusLogs)
	prettyLogrusFields(g.cfg.Logger, "beacon metadata...", metadataLogs)

	// select the random slots to sample
	// limit to only Fulu supported
	custSlots := int64(CustodySlots)
	fuluForkEpoch := g.beaconApi.GetFuluForkEpoch()
	if (int64(remoteStatus.HeadSlot) - int64(CustodySlots)) <= int64((fuluForkEpoch * 32)) {
		custSlots = int64(remoteStatus.HeadSlot) - int64(fuluForkEpoch*32)
	}
	randomSlots := selectRandomSlotsForRange(
		int64(remoteStatus.HeadSlot),
		int64(Samples),
		custSlots,
	)
	randomSlotsLogs := visualizeRandomSlots(randomSlots)
	prettyLogrusFields(g.cfg.Logger, "to request slot->blobs ...", randomSlotsLogs)

	// get the blocks so that we can compare the obtained results with the chain ones
	bBlocks, err := g.fetchSlotBlocks(ctx, randomSlots)
	if err != nil {
		return scanResult, err
	}

	// DAS??!?
	dataCols, err := g.getDataColumnForSlotAndSubnet(ctx, peerInfo.AddrInfo.ID, randomSlots, metadataCustodyIdxs[:])
	if err != nil {
		return scanResult, err
	}

	// evaluate and return the results
	evalResult, err := evaluateColumnResponses(g.cfg.Logger, peerInfo.Enode.ID().String(), randomSlots, metadataCustodyIdxs, bBlocks, dataCols)
	if err != nil {
		return scanResult, err
	}

	scanResult.EvalResult = evalResult
	return scanResult, nil
}

func (g *DasGuardian) MonitorEndpoint(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(12 * time.Second):
			g.cfg.Logger.Info("monitoring node...")
			err := g.monitorEndpoint(ctx)
			if err != nil {
				return err
			}
		}

	}
}

func (g *DasGuardian) monitorEndpoint(ctx context.Context) error {
	// extract the peering details from the ENR
	enrNode, err := ParseNode(g.nodeIdentity.Data.Enr)
	if err != nil {
		return err
	}

	g.cfg.Logger.WithFields(log.Fields{
		"peer-id":     g.nodeIdentity.Data.PeerID,
		"node-id":     enrNode.ID().String(),
		"p2p-addrs":   g.nodeIdentity.Data.Maddrs,
		"discv-addrs": g.nodeIdentity.Data.DiscvAddrs,
	}).Info()

	// compare the results from the API with the ones from the ENR

	if g.beaconApi.GetStateVersion() == "fulu" {
		// cgc
		enrCustody, err := GetCustodyFromEnr(enrNode)
		if err != nil {
			return err
		}
		apiCustody, _ := g.nodeIdentity.CustodyInt()
		if enrCustody != uint64(apiCustody) {
			g.cfg.Logger.WithFields(log.Fields{
				"enr": enrCustody,
				"api": apiCustody,
			}).Warn("enr and api custody don't match")
		}
	}

	// attesnets
	enrAttnets, err := GetAttnetsFromEnr(enrNode)
	if err != nil {
		return fmt.Errorf("failed to get attnets from enr: %v", err)
	}
	apiAttnets := g.nodeIdentity.Attnets()
	if !bytes.Equal(enrAttnets, apiAttnets) {
		g.cfg.Logger.WithFields(log.Fields{
			"enr": enrAttnets,
			"api": apiAttnets,
		}).Warn("enr and api attnets don't match")
	}

	// syncnets
	enrSyncnets, err := GetSyncnetsFromEnr(enrNode)
	if err != nil {
		return fmt.Errorf("failed to get syncnets from enr: %v", err)
	}
	apiSyncnets := g.nodeIdentity.Syncnets()
	if !bytes.Equal(apiSyncnets, apiSyncnets) {
		g.cfg.Logger.WithFields(log.Fields{
			"enr": enrSyncnets,
			"api": apiSyncnets,
		}).Warn("enr and api syncnets don't match")
	}

	// make the scan, and the the results
	invalidSlots := make([]uint64, 0)
	res, err := g.scan(ctx, enrNode)
	if err != nil {
		return err
	}

	for s, slotRes := range res.EvalResult.ValidSlot {
		if !slotRes {
			g.cfg.Logger.Errorf("the monitoring node didn't have the data for slot")
			invalidSlots = append(invalidSlots, res.EvalResult.Slots[s])
		}
	}
	if len(invalidSlots) > 0 {
		return fmt.Errorf("remote node didn't provide complete data-columns for slots %v", invalidSlots)
	}
	g.cfg.Logger.Info("node monitoring done")
	return nil
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

type Libp2pInfo map[string]any

func (g *DasGuardian) ConnectNode(ctx context.Context, addrinfo *peer.AddrInfo, enode *enode.Node) (*PeerInfo, error) {
	// for whatever reason, we need to record the adddress of the peer at the peerstore
	g.host.Peerstore().AddAddrs(addrinfo.ID, addrinfo.Addrs, 24*time.Hour)

	for r := 1; r <= g.cfg.ConnectionRetries; r++ {
		connCtx, connCancel := context.WithTimeout(ctx, g.cfg.ConnectionTimeout)
		startT := time.Now()

		err := g.host.Connect(connCtx, *addrinfo)
		connCancel()
		if err == nil {
			break
		}

		g.cfg.Logger.Warnf("conn attempt %d failed - %s", r, err.Error())
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("main context died %s", ctx.Err().Error())
		case <-time.After(Libp2pConnGraceTime - time.Since(startT)):
			// TODO looks like a bug -- startT resets with every iteration
		}
	}

	// Test if we're indeed connected.
	if g.host.Network().Connectedness(addrinfo.ID) != network.Connected {
		return nil, fmt.Errorf("unreachable node")
	}

	// TODO: subscribe to the identify protocol event and ensure that we return when the peer is identified
	// extract the necessary information from the ethNode
	info := g.libp2pPeerInfo(addrinfo.ID, enode)
	prettyLogrusFields(g.cfg.Logger, "libp2p info", info)
	g.cfg.Logger.Info("attempting ping")

	// Exchange ping.
	// Not all CL clients support ping, so we'll just log errors and move on.
	// TODO could fall back to ICMP ping if important
	startT := time.Now()
	if err := g.rpcServ.Ping(ctx, addrinfo.ID); err != nil {
		g.cfg.Logger.WithError(err).Warn("libp2p ping failed; skipping")
	} else {
		elapsed := time.Since(startT)
		info["ping_rtt"] = elapsed
		g.cfg.Logger.Infof("libp2p RTT: %s", elapsed)
	}

	res := &PeerInfo{
		AddrInfo:   addrinfo,
		Enode:      enode,
		Libp2pInfo: info,
	}
	return res, nil
}

func (g *DasGuardian) libp2pPeerInfo(pid peer.ID, ethNode *enode.Node) map[string]any {
	libp2pMetadata := make(map[string]any)

	// ENR (first in the list as requested)
	if ethNode != nil {
		libp2pMetadata[ENR] = ethNode.String()
	}

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

func (g *DasGuardian) visualizeBeaconStatusV1(status *StatusV1) map[string]any {
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

func (g *DasGuardian) requestBeaconStatusV1(ctx context.Context, pid peer.ID) *StatusV1 {
	status, err := g.rpcServ.StatusV1(ctx, pid, g.localchain.StatusV1)
	if err != nil {
		g.cfg.Logger.Warnf("error requesting beacon-status-v1 - %s", err.Error())
	}

	// Debug: compare local vs remote fork digests
	if status != nil && g.localchain.StatusV1 != nil {
		localForkDigest := fmt.Sprintf("0x%x", g.localchain.StatusV1.ForkDigest)
		remoteForkDigest := fmt.Sprintf("0x%x", status.ForkDigest)
		match := localForkDigest == remoteForkDigest

		g.cfg.Logger.WithFields(log.Fields{
			"peer_id":            pid.String(),
			"local_fork_digest":  localForkDigest,
			"remote_fork_digest": remoteForkDigest,
			"fork_digest_match":  match,
		}).Debug("Fork digest comparison (StatusV1)")

		if !match {
			g.cfg.Logger.Warn("Fork digest mismatch detected - this will cause network incompatibility")
		}
	}

	return status
}

func (g *DasGuardian) visualizeBeaconStatusV2(status *StatusV2) map[string]any {
	statusInfo := make(map[string]any)
	if status != nil {
		// Determine which version was used based on EarliestAvailableSlot
		if status.EarliestAvailableSlot == ^uint64(0) {
			statusInfo[StatusVersion] = "v1 (fallback)"
			statusInfo[EarliestAvailableSlot] = "unavailable"
		} else {
			statusInfo[StatusVersion] = "v2"
			statusInfo[EarliestAvailableSlot] = status.EarliestAvailableSlot
		}

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

func (g *DasGuardian) requestBeaconStatusV2(ctx context.Context, pid peer.ID) *StatusV2 {
	status, err := g.rpcServ.StatusV2(ctx, pid, g.localchain.StatusV2)
	if err != nil {
		g.cfg.Logger.Warnf("error requesting beacon-status-v2 - %s, falling back to status-v1", err.Error())

		// Fallback to status v1 if v2 fails
		statusV1, err := g.rpcServ.StatusV1(ctx, pid, g.localchain.StatusV1)
		if err != nil {
			g.cfg.Logger.Warnf("error requesting beacon-status-v1 fallback - %s", err.Error())
			return nil
		}

		g.cfg.Logger.Debugf("successfully received beacon-status-v1 from peer %s", pid)

		// Convert StatusV1 to StatusV2 format
		return &StatusV2{
			ForkDigest:            statusV1.ForkDigest,
			FinalizedRoot:         statusV1.FinalizedRoot,
			FinalizedEpoch:        statusV1.FinalizedEpoch,
			HeadRoot:              statusV1.HeadRoot,
			HeadSlot:              statusV1.HeadSlot,
			EarliestAvailableSlot: ^uint64(0), // Use max uint64 to indicate unavailable
		}
	}

	// Debug: compare local vs remote fork digests
	if status != nil && g.localchain.StatusV2 != nil {
		localForkDigest := fmt.Sprintf("0x%x", g.localchain.StatusV2.ForkDigest)
		remoteForkDigest := fmt.Sprintf("0x%x", status.ForkDigest)
		match := localForkDigest == remoteForkDigest

		g.cfg.Logger.WithFields(log.Fields{
			"peer_id":            pid.String(),
			"local_fork_digest":  localForkDigest,
			"remote_fork_digest": remoteForkDigest,
			"fork_digest_match":  match,
		}).Debug("Fork digest comparison (StatusV2)")

		if !match {
			g.cfg.Logger.Warn("Fork digest mismatch detected - this will cause network incompatibility")
		}
	}

	g.cfg.Logger.Debugf("successfully received beacon-status-v2 from peer %s", pid)
	return status
}

func (g *DasGuardian) visualizeBeaconMetadataV2(metadata *MetaDataV2) map[string]any {
	metadataInfo := make(map[string]any)
	if metadata != nil {
		metadataInfo[MetadataVersion] = "v2"
		metadataInfo[SeqNumber] = metadata.SeqNumber
		metadataInfo[Attnets] = fmt.Sprintf("0x%x", metadata.Attnets)
		metadataInfo[Syncnets] = fmt.Sprintf("0x%x", metadata.Syncnets)
	} else {
		metadataInfo["beacon-metadata"] = "errored"
	}
	return metadataInfo
}

func (g *DasGuardian) requestBeaconMetadataV2(ctx context.Context, pid peer.ID) *MetaDataV2 {
	metadata, err := g.rpcServ.MetaDataV2(ctx, pid, g.localchain.MetaDataV2)
	if err != nil {
		g.cfg.Logger.Warnf("error requesting beacon-metadata-v2 - %s", err.Error())
	} else {
		g.cfg.Logger.Debugf("successfully received beacon-metadata-v2 from peer %s", pid)
	}
	return metadata
}

func (g *DasGuardian) visualizeBeaconMetadataV3(metadata *MetaDataV3) map[string]any {
	metadataInfo := make(map[string]any)
	if metadata != nil {
		metadataInfo[MetadataVersion] = "v3"
		metadataInfo[SeqNumber] = metadata.SeqNumber
		metadataInfo[Attnets] = fmt.Sprintf("0x%x", metadata.Attnets)
		metadataInfo[Syncnets] = fmt.Sprintf("0x%x", metadata.Syncnets)
		metadataInfo[CustodyGroupCount] = metadata.CustodyGroupCount
	} else {
		metadataInfo["beacon-metadata"] = "errored"
	}
	return metadataInfo
}

func (g *DasGuardian) requestBeaconMetadataV3(ctx context.Context, pid peer.ID) *MetaDataV3 {
	// Debug: Check what protocols the peer supports
	protocols, err := g.host.Network().Peerstore().GetProtocols(pid)
	if err != nil {
		g.cfg.Logger.WithFields(log.Fields{
			"peer_id": pid.String(),
			"error":   err,
		}).Debug("Failed to get peer protocols for MetaDataV3")
	} else {
		hasMetaDataV3 := false
		for _, proto := range protocols {
			if proto == "/eth2/beacon_chain/req/metadata/3/ssz_snappy" {
				hasMetaDataV3 = true
				break
			}
		}
		g.cfg.Logger.WithFields(log.Fields{
			"peer_id":              pid.String(),
			"protocols":            protocols,
			"supports_metadata_v3": hasMetaDataV3,
		}).Debug("Peer protocol support check for MetaDataV3")
	}

	metadata, err := g.rpcServ.MetaDataV3(ctx, pid, g.localchain.MetaDataV3)
	if err != nil {
		g.cfg.Logger.WithFields(log.Fields{
			"peer_id": pid.String(),
			"error":   err.Error(),
		}).Warn("error requesting beacon-metadata-v3")
	} else {
		g.cfg.Logger.Debugf("successfully received beacon-metadata-v3 from peer %s", pid)
	}
	return metadata
}

func (g *DasGuardian) composeLocalBeaconStatus() (*StatusV1, *StatusV2, error) {
	slot := uint64(0)
	if headSlot := g.beaconApi.GetLatestBlockHeader(); headSlot != nil {
		slot = uint64(headSlot.Slot)
	}

	// fork digest
	forkDigest, err := g.beaconApi.GetForkDigest(slot)
	if err != nil {
		return nil, nil, err
	}

	// finalized
	finalizedCheckpoint := g.beaconApi.GetFinalizedCheckpoint()
	finalizedRoot := bytesutil.ToBytes32(finalizedCheckpoint.Root[:])
	finalizedEpoch := uint64(finalizedCheckpoint.Epoch)

	// head
	latestBlockHeader := g.beaconApi.GetLatestBlockHeader()
	headRoot := bytesutil.ToBytes32(latestBlockHeader.StateRoot[:])
	headSlot := uint64(latestBlockHeader.Slot)

	statusV1 := &StatusV1{
		ForkDigest:     [4]byte(forkDigest),
		FinalizedRoot:  finalizedRoot,
		FinalizedEpoch: finalizedEpoch,
		HeadRoot:       headRoot,
		HeadSlot:       headSlot,
	}
	statusV2 := &StatusV2{
		ForkDigest:            [4]byte(forkDigest),
		FinalizedRoot:         finalizedRoot,
		FinalizedEpoch:        finalizedEpoch,
		HeadRoot:              headRoot,
		HeadSlot:              headSlot,
		EarliestAvailableSlot: headSlot,
	}

	return statusV1, statusV2, nil
}

func (g *DasGuardian) composeLocalBeaconMetadata() (*MetaDataV2, *MetaDataV3) {
	metadataV2 := &MetaDataV2{
		SeqNumber: 0,
		Attnets:   [8]byte(g.nodeIdentity.Attnets()),
		Syncnets:  [1]byte(g.nodeIdentity.Syncnets()),
	}
	metadataV3 := &MetaDataV3{
		SeqNumber:         0,
		Attnets:           [8]byte(g.nodeIdentity.Attnets()),
		Syncnets:          [1]byte(g.nodeIdentity.Syncnets()),
		CustodyGroupCount: uint64(128),
	}
	return metadataV2, metadataV3
}

func (g *DasGuardian) getDataColumnForSlotAndSubnet(ctx context.Context, pid peer.ID, slots []uint64, columnIdxs []uint64) ([][]*DataColumnSidecarV1, error) {
	g.cfg.Logger.WithFields(log.Fields{
		"slots":   len(slots),
		"columns": len(columnIdxs),
	}).Info("sampling node for...")

	// TODO: make sure that we limit the number of columns that we request (slots * idxs * columns)
	dataColumns := make([][]*DataColumnSidecarV1, len(slots))

	startT := time.Now()
	// make the request for each slots
	for s, slot := range slots {
		// make the request per each column
		duration, cols, err := g.rpcServ.DataColumnByRangeV1(ctx, pid, slot, columnIdxs)
		if err != nil {
			g.cfg.Logger.Error(err)
			return dataColumns, err
		}
		dataColumns[s] = cols

		// compose the results
		g.cfg.Logger.WithFields(log.Fields{
			"req-duration": duration,
			"slot":         slot,
			"das-result":   fmt.Sprintf("%d/%d columns", len(cols), len(columnIdxs)),
		}).Info("req info...")
	}

	opDur := time.Since(startT)
	g.cfg.Logger.WithFields(log.Fields{
		"duration": opDur,
	}).Info("node custody sampling done...")
	return dataColumns, nil
}

func (g *DasGuardian) fetchSlotBlocks(ctx context.Context, slots []uint64) ([]*spec.VersionedSignedBeaconBlock, error) {
	g.cfg.Logger.WithFields(log.Fields{
		"slots": slots,
	}).Info("requesting slot-blocks from beacon API...")
	blocks := make([]*spec.VersionedSignedBeaconBlock, len(slots))
	for i, slot := range slots {
		b, err := g.beaconApi.GetBeaconBlock(ctx, slot)
		if err != nil {
			return blocks, err
		}
		blocks[i] = b
	}
	return blocks, nil
}
