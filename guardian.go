package dasguardian

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	"github.com/OffchainLabs/prysm/v6/encoding/bytesutil"
	"github.com/pkg/errors"
	bitfield "github.com/prysmaticlabs/go-bitfield"

	"github.com/probe-lab/eth-das-guardian/api"

	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/encoder"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"

	libp2p "github.com/libp2p/go-libp2p"
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
	ApiStateTimeout     = 30 * time.Second
	ApiQueryTimeout     = 10 * time.Second
	FuluSupportRetry    = 12 * time.Second // 1 slot

	Samples             = uint64(4)         // TODO: hardcoded
	CustodySlots        = uint64(4096 * 32) // default custody in the fulu specs
	FuluForkScheduleIdx = 6                 //  Fulu is the 7th fork -> index = 6
)

const (
	// libp2p related metadata
	UserAgent       = "user_agent"
	Protocols       = "protocols"
	Maddrss         = "multiaddresses"
	PeerID          = "peer_id"
	ProtocolVersion = "protocol_version"
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
	// values
	DataColumnSidecarSubnetCount = uint64(128)
)
type DasGuardianConfig struct {
	Libp2pHost        string
	Libp2pPort        int
	ConnectionRetries int
	ConnectionTimeout time.Duration
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
	cfg           *DasGuardianConfig
	forkSchedules api.ForkSchedule

	// services
	host    host.Host
	apiCli  *api.Client
	pubsub  *pubsub.PubSub
	rpcServ *ReqResp

	// chain data
	stateM sync.RWMutex
	state  *api.PeerDASstate

	// pre-fulu
	electraM        sync.RWMutex
	electraStatus   *pb.Status
	electraMetadata *pb.MetaDataV1

	// post-fulu
	fuluM        sync.RWMutex
	fuluStatus   *pb.StatusV2
	fuluMetadata *pb.MetaDataV2
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
		cfg:             cfg,
		host:            h,
		pubsub:          pubsub,
		apiCli:          apiCli,
		state:           &api.PeerDASstate{},
		electraStatus:   &pb.Status{},
		electraMetadata: &pb.MetaDataV1{},
		fuluStatus:      &pb.StatusV2{},
		fuluMetadata:    &pb.MetaDataV2{},
	}

	if err := guardian.init(ctx); err != nil {
		return nil, err
	}

	return guardian, nil
}

func (g *DasGuardian) init(ctx context.Context) error {
	initCtx, initCancel := context.WithTimeout(ctx, g.cfg.InitTimeout)
	defer initCancel()

	// check api connection
	if err := g.apiCli.CheckConnection(initCtx); err != nil {
		return fmt.Errorf("connection to %s was stablished, but not active - %s", g.cfg.BeaconAPIendpoint, err.Error())
	}
	log.Info("connected to the beacon API...")

	// get the network configuration from the apiCli
	forkSchedules, err := g.apiCli.GetNetworkConfig(initCtx)
	if err != nil {
		return err
	}
	g.forkSchedules = forkSchedules.Data[FuluForkScheduleIdx] // we only need the fulu specifics

	// compose and get the local Metadata
	g.stateM.Lock()
	g.state, err = g.apiCli.GetPeerDASstate(initCtx)
	g.stateM.Unlock()
	if err != nil {
		return err
	}

	fuluForkEpoch, err := strconv.Atoi(g.forkSchedules.Epoch)
	if err != nil {
		return err
	}
	g.stateM.RLock()
	currentSlot := int(g.state.Data.Slot)
	currentVersion := g.state.Version
	g.stateM.RUnlock()
	if (currentSlot / 32) < fuluForkEpoch {
		secondsToFulu := time.Duration(((fuluForkEpoch*32)-currentSlot)*12) * time.Second
		log.Warnf("network doesn't support fulu yet")
		log.Warnf("current: (slot: %d epoch: %d - version: %s)", currentSlot, (currentSlot / 32), currentVersion)
		log.Warnf("target:  (slot: %d epoch: %d - missing: %d = %s)", fuluForkEpoch*32, fuluForkEpoch, (fuluForkEpoch*32)-currentSlot, secondsToFulu)
		go func() {
			log.Info("waiting for ", secondsToFulu)
			if secondsToFulu < 0 {
				log.Error("neg time to fulu?!")
				return
			}
			select {
			case <-ctx.Done():
				log.Error("tooled closed without reaching fulu upgrade")
				return

			case <-time.After(secondsToFulu):
				g.stateM.Lock()
				g.state, err = g.apiCli.GetPeerDASstate(ctx)
				g.stateM.Unlock()
				if err != nil {
					log.Errorf("unable to get the Beacon State after Fulu - %s", err.Error())
					return
				}
			}
		}()
	} else {
		log.Info("fulu is supported")
		fmt.Sprintln(currentSlot/32, fuluForkEpoch)
	}

	g.stateM.RLock()
	prettyLogrusFields("dowloaded beacon head-state", map[string]any{
		"version":       g.state.Version,
		"finalized":     g.state.Finalized,
		"optimistic-el": g.state.ExecutionOptimistic,
		"validators":    len(g.state.Data.Validators),
	})
	g.stateM.RUnlock()

	err = g.composeLocalBeaconStaus()
	if err != nil {
		return err
	}

	err = g.composeLocalBeaconMetadata()
	if err != nil {
		return err
	}

	// subscribe to main topics
	forkD := g.state.Data.Fork.String()
	if err = g.subscribeToTopics(initCtx, getMandatoryTopics(forkD)); err != nil {
		return err
	}

	// register the rpc module
	reqRespCfg := &ReqRespConfig{
		Encoder:      &encoder.SszNetworkEncoder{},
		ReadTimeout:  g.cfg.ConnectionTimeout,
		WriteTimeout: g.cfg.ConnectionTimeout,
	}
	reqResp, err := NewReqResp(g.host, reqRespCfg)
	if err != nil {
		return err
	}
	if err := reqResp.RegisterHandlers(initCtx); err != nil {
		return err
	}
	g.rpcServ = reqResp

	return nil
}

func (g *DasGuardian) Scan(ctx context.Context, ethNode *enode.Node) (DASEvaluationResult, error) {
	return g.scan(ctx, ethNode)
}

func (g *DasGuardian) ScanMultiple(ctx context.Context, concurrency int32, ethNodes []*enode.Node) ([]DASEvaluationResult, error) {
	dasResults := make([]DASEvaluationResult, 0, len(ethNodes))
	scanC := make(chan *enode.Node, concurrency)
	resultC := make(chan DASEvaluationResult)

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
				log.WithField("node_id", ethNode.ID().String()).Error("")
			}
			res.Error = err
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

func (g *DasGuardian) scan(ctx context.Context, ethNode *enode.Node) (DASEvaluationResult, error) {
	switch g.getCurrentStateVersion() {
	case "electra":
		return g.scanElectra(ctx, ethNode)
	case "fulu":
		return g.scanFulu(ctx, ethNode)
	default:
		return DASEvaluationResult{}, fmt.Errorf("not recognized fork for the state %s", g.state.Version)
	}

}

func (g *DasGuardian) scanElectra(ctx context.Context, ethNode *enode.Node) (DASEvaluationResult, error) {
	// get the info from the ENR
	enodeAddr, err := ParseMaddrFromEnode(ethNode)
	if err != nil {
		return DASEvaluationResult{}, err
	}

	// connection attempt using the libp2p host
	if err := g.ConnectNode(ctx, enodeAddr); err != nil {
		return DASEvaluationResult{}, err
	}

	// extract the necessary information from the ethNode
	libp2pInfo := g.libp2pPeerInfo(enodeAddr.ID)

	// exchange ping
	startT := time.Now()
	if err := g.rpcServ.Ping(ctx, enodeAddr.ID); err != nil {
		return DASEvaluationResult{}, nil
	}
	libp2pInfo["ping_rtt"] = time.Since(startT)
	prettyLogrusFields("libp2p info...", libp2pInfo)

	// exchange beacon-status
	remoteStatus := g.requestBeaconStatusV1(ctx, enodeAddr.ID)
	if remoteStatus == nil {
		return DASEvaluationResult{}, fmt.Errorf("failed to get beacon status from peer %s", enodeAddr.ID)
	}
	statusLogs := g.visualizeBeaconStatusV1(remoteStatus)

	// exchange beacon-metadata
	remoteMetadata := g.requestBeaconMetadataV2(ctx, enodeAddr.ID)
	if remoteMetadata == nil {
		return DASEvaluationResult{}, fmt.Errorf("failed to get beacon metadata from peer %s", enodeAddr.ID)
	}
	metadataLogs := g.visualizeBeaconMetadataV2(remoteMetadata)

	prettyLogrusFields("scanning eth-node...", map[string]any{
		"peer-id": enodeAddr.ID.String(),
		"maddr":   enodeAddr.Addrs,
	})
	prettyLogrusFields("beacon status...", statusLogs)
	prettyLogrusFields("beacon metadata...", metadataLogs)

	return DASEvaluationResult{}, nil
}

func (g *DasGuardian) scanFulu(ctx context.Context, ethNode *enode.Node) (DASEvaluationResult, error) {
	// get the info from the ENR
	enodeAddr, err := ParseMaddrFromEnode(ethNode)
	if err != nil {
		return DASEvaluationResult{}, err
	}

	enrCustody, err := GetCustodyFromEnr(ethNode)
	if err != nil {
		log.Warn(err.Error())
	}
	enrCustodyGroups, err := CustodyColumnsSlice(ethNode.ID(), enrCustody, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
	if err != nil {
		return DASEvaluationResult{}, err
	}

	// connection attempt using the libp2p host
	if err := g.ConnectNode(ctx, enodeAddr); err != nil {
		return DASEvaluationResult{}, err
	}

	// extract the necessary information from the ethNode
	libp2pInfo := g.libp2pPeerInfo(enodeAddr.ID)

	// exchange ping
	startT := time.Now()
	if err := g.rpcServ.Ping(ctx, enodeAddr.ID); err != nil {
		return DASEvaluationResult{}, nil
	}
	libp2pInfo["ping_rtt"] = time.Since(startT)
	prettyLogrusFields("libp2p info...", libp2pInfo)

	// exchange beacon-status
	remoteStatus := g.requestBeaconStatusV2(ctx, enodeAddr.ID)
	if remoteStatus == nil {
		return DASEvaluationResult{}, fmt.Errorf("failed to get beacon status from peer %s", enodeAddr.ID)
	}
	statusLogs := g.visualizeBeaconStatusV2(remoteStatus)
	prettyLogrusFields("remote status-v2", statusLogs)

	// exchange beacon-metadata
	remoteMetadata := g.requestBeaconMetadataV3(ctx, enodeAddr.ID)
	if remoteMetadata == nil {
		return DASEvaluationResult{}, fmt.Errorf("failed to get beacon metadata from peer %s", enodeAddr.ID)
	}
	metadataLogs := g.visualizeBeaconMetadataV3(remoteMetadata)
	prettyLogrusFields("remote metadata-v3", metadataLogs)
	metadataCustodyIdxs, err := CustodyColumnsSlice(ethNode.ID(), remoteMetadata.CustodyGroupCount, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
	if err != nil {
		return DASEvaluationResult{}, errors.Wrap(err, "wrong cuystody subnet")
	}

	// compare enr custody to metadata one
	if enrCustody != remoteMetadata.CustodyGroupCount {
		log.Warnf("enr custody (%d) mismatches metadata RPC one (%d)", enrCustody, remoteMetadata.CustodyGroupCount)
	}

	prettyLogrusFields("scanning eth-node...", map[string]any{
		"peer-id":            enodeAddr.ID.String(),
		"maddr":              enodeAddr.Addrs,
		"enr-custody":        enrCustody,
		"enr-custody-groups": enrCustodyGroups,
	})
	prettyLogrusFields("beacon status...", statusLogs)
	prettyLogrusFields("beacon metadata...", metadataLogs)

	// select the random slots to sample
	// limit to only Fulu supported
	custSlots := int64(CustodySlots)
	fuluForkEpoch, err := strconv.Atoi(g.forkSchedules.Epoch)
	if err != nil {
		log.Error("convert fork-schedule epoch to int - ", err)
	}
	if (int64(remoteStatus.HeadSlot) - int64(CustodySlots)) <= int64((fuluForkEpoch * 32)) {
		custSlots = int64(remoteStatus.HeadSlot) - int64(fuluForkEpoch*32)
	}
	randomSlots := selectRandomSlotsForRange(
		int64(remoteStatus.HeadSlot),
		int64(Samples),
		custSlots,
	)
	randomSlotsLogs := visualizeRandomSlots(randomSlots)
	prettyLogrusFields("to request slot->blobs ...", randomSlotsLogs)

	// get the blocks so that we can compare the obtained results with the chain ones
	bBlocks, err := g.fetchSlotBlocks(ctx, randomSlots)
	if err != nil {
		return DASEvaluationResult{}, err
	}

	// DAS??!?
	dataCols, err := g.getDataColumnForSlotAndSubnet(ctx, enodeAddr.ID, randomSlots, metadataCustodyIdxs[:])
	if err != nil {
		return DASEvaluationResult{}, err
	}

	// evaluate and return the results
	return evaluateColumnResponses(ethNode.ID().String(), randomSlots, metadataCustodyIdxs, bBlocks, dataCols)
}

func (g *DasGuardian) MonitorEndpoint(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil

		case <-time.After(12 * time.Second):
			log.Info("monitoring node...")
			err := g.monitorEndpoint(ctx)
			if err != nil {
				return err
			}
		}
	}
}

func (g *DasGuardian) monitorEndpoint(ctx context.Context) error {
	// get the information directly from the Beacon API
	nodeInfo, err := g.apiCli.GetNodeIdentity(ctx)
	if err != nil {
		return err
	}
	// extract the peering details from the ENR
	enrNode, err := ParseNode(nodeInfo.Data.Enr)
	if err != nil {
		return err
	}

	log.WithFields(log.Fields{
		"peer-id":     nodeInfo.Data.PeerID,
		"node-id":     enrNode.ID().String(),
		"p2p-addrs":   nodeInfo.Data.Maddrs,
		"discv-addrs": nodeInfo.Data.DiscvAddrs,
	}).Info()

	// compare the results from the API with the ones from the ENR

	// cgc
	enrCustody, err := GetCustodyFromEnr(enrNode)
	if err != nil {
		return err
	}
	apiCustody, _ := nodeInfo.CustodyInt()
	if enrCustody != uint64(apiCustody) {
		log.WithFields(log.Fields{
			"enr": enrCustody,
			"api": apiCustody,
		}).Warn("enr and api custody don't match")
	}

	// attesnets
	enrAttnets := GetAttnetsFromEnr(enrNode)
	apiAttnets := nodeInfo.Attnets()
	if enrAttnets != apiAttnets {
		log.WithFields(log.Fields{
			"enr": enrAttnets,
			"api": apiAttnets,
		}).Warn("enr and api attnets don't match")
	}

	// syncnets
	enrSyncnets := GetSyncnetsFromEnr(enrNode)
	apiSyncnets := nodeInfo.Syncnets()
	if enrAttnets != apiAttnets {
		log.WithFields(log.Fields{
			"enr": enrSyncnets,
			"api": apiSyncnets,
		}).Warn("enr and api syncnets don't match")
	}

	// make the scan, and the the results
	invalidSlots := make([]uint64, 0)
	res, err := g.scan(ctx, enrNode)
	for s, slotRes := range res.ValidSlot {
		if !slotRes {
			log.Errorf("the monitoring node didn't have the data for slot")
			invalidSlots = append(invalidSlots, res.Slots[s])
		}
	}
	if len(invalidSlots) > 0 {
		return fmt.Errorf("remote node didn't provide complete data-columns for slots %v", invalidSlots)
	}
	log.Info("node monitoring done")
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

func (g *DasGuardian) ConnectNode(ctx context.Context, pInfo *peer.AddrInfo) error {
	// TODO: subscribe to the identify protocol event and ensure that we return when the peer is identified

	// for whatever reason, we need to record the adddress of the peer at the peerstore
	g.host.Peerstore().AddAddrs(pInfo.ID, pInfo.Addrs, 24*time.Hour)

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
			log.Info("connected to remote node...")
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

func (g *DasGuardian) visualizeBeaconStatusV1(status *pb.Status) map[string]any {
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

func (g *DasGuardian) visualizeBeaconStatusV2(status *pb.StatusV2) map[string]any {
	statusInfo := make(map[string]any)
	if status != nil {
		statusInfo[ForkDigest] = fmt.Sprintf("0x%x", status.ForkDigest)
		statusInfo[FinalizedEpoch] = status.FinalizedEpoch
		statusInfo[FinalizedRoot] = fmt.Sprintf("0x%x", status.FinalizedRoot)
		statusInfo[HeadRoot] = fmt.Sprintf("0x%x", status.HeadRoot)
		statusInfo[HeadSlot] = status.HeadSlot
		statusInfo[EarliestAvailableSlot] = status.EarliestAvailableSlot
	} else {
		statusInfo["beacon-status"] = "errored"
	}
	return statusInfo
}

func (g *DasGuardian) requestBeaconStatusV1(ctx context.Context, pid peer.ID) *pb.Status {
	g.electraM.RLock()
	defer g.electraM.Unlock()
	status, err := g.rpcServ.StatusV1(ctx, pid, g.electraStatus)
	if err != nil {
		log.Warnf("error requesting beacon-status-v1 - %s", err.Error())
	}
	return status
}

func (g *DasGuardian) requestBeaconStatusV2(ctx context.Context, pid peer.ID) *pb.StatusV2 {
	// TODO: probably better to lock the state here as well to read the status
	g.fuluM.RLock()
	defer g.fuluM.RUnlock()
	status, err := g.rpcServ.StatusV2(ctx, pid, g.fuluStatus)
	if err != nil {
		log.Warnf("error requesting beacon-status-v2 - %s", err.Error())
	}
	return status
}

func (g *DasGuardian) visualizeBeaconMetadataV2(metadata *pb.MetaDataV1) map[string]any {
	metadataInfo := make(map[string]any)
	if metadata != nil {
		metadataInfo[SeqNumber] = metadata.SeqNumber
		metadataInfo[Attnets] = fmt.Sprintf("0x%x", metadata.Attnets.Bytes())
		metadataInfo[Syncnets] = fmt.Sprintf("0x%x", metadata.Syncnets.Bytes())
	} else {
		metadataInfo["beacon-metadata"] = "errored"
	}
	return metadataInfo
}

func (g *DasGuardian) visualizeBeaconMetadataV3(metadata *pb.MetaDataV2) map[string]any {
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

func (g *DasGuardian) requestBeaconMetadataV2(ctx context.Context, pid peer.ID) *pb.MetaDataV1 {
	g.electraM.RLock()
	defer g.electraM.RUnlock()
	metadata, err := g.rpcServ.MetaDataV2(ctx, pid, g.electraMetadata)
	if err != nil {
		log.Warnf("error requesting beacon-metadata-v2 - %s", err.Error())
	}
	return metadata
}

func (g *DasGuardian) requestBeaconMetadataV3(ctx context.Context, pid peer.ID) *pb.MetaDataV2 {
	g.fuluM.RLock()
	defer g.fuluM.RUnlock()
	metadata, err := g.rpcServ.MetaDataV3(ctx, pid, g.fuluMetadata)
	if err != nil {
		log.Warnf("error requesting beacon-metadata-v3 - %s", err.Error())
	}
	return metadata
}

func (g *DasGuardian) composeLocalBeaconStaus() error {
	switch g.getCurrentStateVersion() {
	case "electra":
		return g.composeElectraBeaconStatus()
	case "fulu":
		return g.composeFuluBeaconStatus()
	default:
		return fmt.Errorf("not recognized fork for the state %s", g.state.Version)
	}
}

func (g *DasGuardian) composeElectraBeaconStatus() error {
	// the composeBeaconStatus already has the rLock of the state
	// fork digest
	forkDigest, err := computePreFuluForkDigest(
		g.state.Data.Fork.CurrentVersion[:],
		g.state.Data.GenesisValidatorsRoot[:],
	)
	if err != nil {
		return err
	}

	// finalized
	finalizedRoot := bytesutil.ToBytes32(g.state.Data.FinalizedCheckpoint.Root[:])
	finalizedEpoch := primitives.Epoch(g.state.Data.FinalizedCheckpoint.Epoch)

	// head
	headRoot := bytesutil.ToBytes32(g.state.Data.LatestBlockHeader.StateRoot[:])
	headSlot := primitives.Slot(g.state.Data.LatestBlockHeader.Slot)

	g.electraM.Lock()
	g.electraStatus = &pb.Status{
		ForkDigest:     forkDigest,
		FinalizedRoot:  finalizedRoot[:],
		FinalizedEpoch: finalizedEpoch,
		HeadRoot:       headRoot[:],
		HeadSlot:       headSlot,
	}
	g.electraM.Unlock()

	prettyLogrusFields("local beacon-status", map[string]any{
		"head-slot":   headSlot,
		"fork-digest": fmt.Sprintf("0x%x", forkDigest),
	})

	return nil
}

func (g *DasGuardian) composeFuluBeaconStatus() error {
	// TODO: fix this to support he BPO forks
	forkDigest, err := computePreFuluForkDigest(
		g.state.Data.Fork.CurrentVersion[:],
		g.state.Data.GenesisValidatorsRoot[:],
	)
	// is this a hotfix?
	forkDigest, err = hex.DecodeString("b62f2b0e")
	if err != nil {
		return err
	}
	if err != nil {
		return err
	}

	// finalized
	finalizedRoot := bytesutil.ToBytes32(g.state.Data.FinalizedCheckpoint.Root[:])
	finalizedEpoch := primitives.Epoch(g.state.Data.FinalizedCheckpoint.Epoch)

	// head
	headRoot := bytesutil.ToBytes32(g.state.Data.LatestBlockHeader.StateRoot[:])
	headSlot := primitives.Slot(g.state.Data.LatestBlockHeader.Slot)

	g.fuluM.Lock()
	g.fuluStatus = &pb.StatusV2{
		ForkDigest:            forkDigest,
		FinalizedRoot:         finalizedRoot[:],
		FinalizedEpoch:        finalizedEpoch,
		HeadRoot:              headRoot[:],
		HeadSlot:              headSlot,
		EarliestAvailableSlot: headSlot,
	}
	g.fuluM.Unlock()

	prettyLogrusFields("local beacon-status", map[string]any{
		"head-slot":   headSlot,
		"fork-digest": fmt.Sprintf("0x%x", forkDigest),
	})

	return nil
}

func (g *DasGuardian) composeLocalBeaconMetadata() error {
	switch g.getCurrentStateVersion() {
	case "electra":
		return g.composeElectraMetadata()
	case "fulu":
		return g.composeFuluMetadata()
	default:
		return fmt.Errorf("not recognized fork for the state %s", g.state.Version)
	}
}

func (g *DasGuardian) composeElectraMetadata() error {
	g.electraM.Lock()
	g.electraMetadata = &pb.MetaDataV1{
		SeqNumber: 0,
		Attnets:   bitfield.NewBitvector64(),
		Syncnets:  bitfield.Bitvector4{byte(0x00)},
	}
	prettyLogrusFields("local beacon-metadata-v1", map[string]any{
		"seq":      g.electraMetadata.SeqNumber,
		"attnets":  fmt.Sprintf("0x%x", g.electraMetadata.Attnets),
		"syncnets": fmt.Sprintf("0x%x", g.electraMetadata.Syncnets),
	})
	g.electraM.Unlock()
	return nil
}

func (g *DasGuardian) composeFuluMetadata() error {
	g.fuluM.Lock()
	g.fuluMetadata = &pb.MetaDataV2{
		SeqNumber:         0,
		Attnets:           bitfield.NewBitvector64(),
		Syncnets:          bitfield.Bitvector4{byte(0x00)},
		CustodyGroupCount: uint64(0),
	}
	g.fuluM.Unlock()
	prettyLogrusFields("local beacon-metadata-v1", map[string]any{
		"seq":      g.fuluMetadata.SeqNumber,
		"attnets":  fmt.Sprintf("0x%x", g.fuluMetadata.Attnets),
		"syncnets": fmt.Sprintf("0x%x", g.fuluMetadata.Syncnets),
		"cgc":      g.fuluMetadata.CustodyGroupCount,
	})
	return nil
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
		g.stateM.Lock()
		duration, cols, err := g.rpcServ.DataColumnByRangeV1(ctx, pid, slot, columnIdxs, g.getCurrentForkDigest())
		g.stateM.RUnlock()
		if err != nil {
			log.Error(err)
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

func (g *DasGuardian) fetchSlotBlocks(ctx context.Context, slots []uint64) ([]*api.BeaconBlock, error) {
	log.WithFields(log.Fields{
		"slots": slots,
	}).Info("requesting slot-blocks from beacon API...")
	blocks := make([]*api.BeaconBlock, len(slots))
	for i, slot := range slots {
		b, err := g.apiCli.GetBeaconBlock(ctx, slot)
		if err != nil {
			return blocks, err
		}
		if b.Data.Message.Slot == "" {
			log.Warnf("block for slot %d was missing", slot)
			blocks[i] = nil
		} else {
			blocks[i] = &b
		}
	}
	return blocks, nil
}

func (g *DasGuardian) getCurrentStateVersion() string {
	g.stateM.RLock()
	defer g.stateM.RUnlock()
	return g.state.Version

}

func (g *DasGuardian) getCurrentForkDigest() []byte {
	switch g.getCurrentStateVersion() {
	case "electra":
		g.electraM.RLock()
		defer g.electraM.RUnlock()
		return g.electraStatus.ForkDigest
	case "fulu":
		g.fuluM.RLock()
		defer g.fuluM.RUnlock()
		return g.fuluStatus.ForkDigest
	default:
		return []byte{}
	}
}
