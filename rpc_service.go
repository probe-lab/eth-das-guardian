package dasguardian

import (
	"context"
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	log "github.com/sirupsen/logrus"
)

var (
	RPCStatusV2 = "/eth2/beacon_chain/req/status/2"
)

const (
	// Spec defined codes.
	GoodbyeCodeClientShutdown uint64 = iota + 1
	GoodbyeCodeWrongNetwork
	GoodbyeCodeGenericError

	// Teku specific codes
	GoodbyeCodeUnableToVerifyNetwork = uint64(128)

	// Lighthouse specific codes
	GoodbyeCodeTooManyPeers = uint64(129)
	GoodbyeCodeBadScore     = uint64(250)
	GoodbyeCodeBanned       = uint64(251)
)

// GoodbyeCodeMessages defines a mapping between goodbye codes and string messages.
var GoodbyeCodeMessages = map[uint64]string{
	GoodbyeCodeClientShutdown:        "client shutdown",
	GoodbyeCodeWrongNetwork:          "irrelevant network",
	GoodbyeCodeGenericError:          "fault/error",
	GoodbyeCodeUnableToVerifyNetwork: "unable to verify network",
	GoodbyeCodeTooManyPeers:          "client has too many peers",
	GoodbyeCodeBadScore:              "peer score too low",
	GoodbyeCodeBanned:                "client banned this node",
}

type ReqRespConfig struct {
	Logger       log.FieldLogger
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	ForkDigest   func(slot uint64) []byte
}

// ReqResp implements the request response domain of the eth2 RPC spec:
// https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/p2p-interface.md
type ReqResp struct {
	host host.Host
	cfg  *ReqRespConfig
}

type ContextStreamHandler func(context.Context, network.Stream) error

func NewReqResp(h host.Host, cfg *ReqRespConfig) (*ReqResp, error) {
	if cfg == nil {
		return nil, fmt.Errorf("req resp server config must not be nil")
	}
	return &ReqResp{
		host: h,
		cfg:  cfg,
	}, nil
}

// RegisterHandlers registers all RPC handlers. It checks first if all
// preconditions are met. This includes valid initial status and metadata
// values.
func (r *ReqResp) RegisterHandlers(ctx context.Context) error {
	handlers := map[string]ContextStreamHandler{
		RPCPingTopicV1:                      r.pingHandler,
		RPCGoodByeTopicV1:                   r.goodbyeHandler,
		RPCStatusTopicV1:                    r.dummyHandler,
		RPCMetaDataTopicV1:                  r.dummyHandler,
		RPCMetaDataTopicV2:                  r.dummyHandler,
		RPCMetaDataTopicV3:                  r.dummyHandler,
		RPCBlocksByRootTopicV1:              r.dummyHandler,
		RPCBlocksByRootTopicV2:              r.dummyHandler,
		RPCBlocksByRangeTopicV1:             r.dummyHandler,
		RPCBlocksByRangeTopicV2:             r.dummyHandler,
		RPCBlobSidecarsByRangeTopicV1:       r.dummyHandler,
		RPCBlobSidecarsByRootTopicV1:        r.dummyHandler,
		RPCDataColumnSidecarsByRangeTopicV1: r.dummyHandler,
		RPCDataColumnSidecarsByRootTopicV1:  r.dummyHandler,
	}

	for id, handler := range handlers {
		r.cfg.Logger.WithField("protocol", id).Debug("Register protocol handler...")
		r.host.SetStreamHandler(protocol.ID(id), r.wrapStreamHandler(ctx, id, handler))
	}

	return nil
}

func (r *ReqResp) wrapStreamHandler(ctx context.Context, name string, handler ContextStreamHandler) network.StreamHandler {
	return func(s network.Stream) {
		// Reset is a no-op if the stream is already closed. Closing the stream
		// is the responsibility of the handler.
		defer s.Reset()

		// time the request handling
		err := handler(ctx, s)
		if err != nil {
			r.cfg.Logger.WithFields(log.Fields{
				"protocol":    s.Protocol(),
				"error":       err,
				"remote-peer": s.Conn().RemotePeer().String(),
			}).Debug("failed handling rpc")
		}
	}
}

func (r *ReqResp) pingHandler(ctx context.Context, stream network.Stream) error {
	req := uint64(0)
	if err := r.readRequest(stream, &req); err != nil {
		return fmt.Errorf("read sequence number: %w", err)
	}

	sq := uint64(23)
	if err := r.writeResponse(stream, &sq); err != nil {
		r.cfg.Logger.Error("write sequence number", err)
	}
	return stream.Close()
}

func (r *ReqResp) goodbyeHandler(ctx context.Context, stream network.Stream) error {
	req := uint64(0)
	if err := r.readRequest(stream, &req); err != nil {
		return fmt.Errorf("read sequence number: %w", err)
	}
	reason := ParseGoodByeReason(req)
	r.cfg.Logger.WithFields(log.Fields{
		"peer_id":  stream.Conn().RemotePeer().String(),
		"err_code": req,
		"reason":   reason,
	}).Warnf("received GoodBye from %s", stream.Conn().RemotePeer().String())
	return stream.Close()
}

func ParseGoodByeReason(num uint64) string {
	reason, ok := GoodbyeCodeMessages[num]
	if ok {
		return reason
	}
	return "unknown"
}

// Beacon Metadata
func (r *ReqResp) dummyHandler(ctx context.Context, stream network.Stream) error {
	// we should delay a little bit the the reset of the request
	// this would give us some margin to request all the info that we want
	select {
	case <-time.After(5 * time.Second):
		break
	case <-ctx.Done():
		break
	}
	return stream.Reset()
}
