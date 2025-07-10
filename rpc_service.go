package dasguardian

import (
	"context"
	"fmt"
	"io"
	"time"

	ssz "github.com/ferranbt/fastssz"

	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p"
	"github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/encoder"
	p2ptypes "github.com/OffchainLabs/prysm/v6/beacon-chain/p2p/types"
	"github.com/OffchainLabs/prysm/v6/consensus-types/primitives"
	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	log "github.com/sirupsen/logrus"
)

var (
	RPCStatusV2 = "/eth2/beacon_chain/req/status/2"
)

type ReqRespConfig struct {
	Logger       log.FieldLogger
	Encoder      encoder.NetworkEncoding
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// local metadata
	BeaconStatus   *pb.StatusV2
	BeaconMetadata *pb.MetaDataV2
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
		p2p.RPCPingTopicV1:                r.pingHandler,
		p2p.RPCGoodByeTopicV1:             r.goodbyeHandler,
		p2p.RPCStatusTopicV1:              r.dummyHandler,
		p2p.RPCMetaDataTopicV1:            r.dummyHandler,
		p2p.RPCMetaDataTopicV2:            r.dummyHandler,
		p2p.RPCMetaDataTopicV3:            r.dummyHandler,
		p2p.RPCBlocksByRootTopicV1:        r.dummyHandler,
		p2p.RPCBlocksByRootTopicV2:        r.dummyHandler,
		p2p.RPCBlocksByRangeTopicV1:       r.dummyHandler,
		p2p.RPCBlocksByRangeTopicV2:       r.dummyHandler,
		p2p.RPCBlobSidecarsByRangeTopicV1: r.dummyHandler,
		p2p.RPCBlobSidecarsByRootTopicV1:  r.dummyHandler,
		p2p.DataColumnSidecarsByRangeName: r.dummyHandler,
		p2p.DataColumnSidecarsByRootName:  r.dummyHandler,
	}

	for id, handler := range handlers {
		protocolID := r.protocolID(id)
		r.cfg.Logger.WithField("protocol", protocolID).Debug("Register protocol handler...")
		r.host.SetStreamHandler(protocolID, r.wrapStreamHandler(ctx, string(protocolID), handler))
	}

	return nil
}

func (r *ReqResp) protocolID(topic string) protocol.ID {
	return protocol.ID(topic + r.cfg.Encoder.ProtocolSuffix())
}

// read-write functions
func (r *ReqResp) readRequest(ctx context.Context, stream network.Stream, data ssz.Unmarshaler) (err error) {
	if err = stream.SetReadDeadline(time.Now().Add(r.cfg.ReadTimeout)); err != nil {
		return fmt.Errorf("failed setting read deadline on stream: %w", err)
	}

	if err = r.cfg.Encoder.DecodeWithMaxLength(stream, data); err != nil {
		return fmt.Errorf("read request data %T: %w", data, err)
	}

	if err = stream.CloseRead(); err != nil {
		return fmt.Errorf("failed to close reading side of stream: %w", err)
	}

	return nil
}

func (r *ReqResp) readResponse(ctx context.Context, stream network.Stream, data ssz.Unmarshaler) (err error) {
	if err = stream.SetReadDeadline(time.Now().Add(r.cfg.ReadTimeout)); err != nil {
		return fmt.Errorf("failed setting read deadline on stream: %w", err)
	}

	code := make([]byte, 1)
	if _, err := io.ReadFull(stream, code); err != nil {
		return fmt.Errorf("failed reading response code: %w", err)
	}

	// code == 0 means success
	// code != 0 means error
	if int(code[0]) != 0 {
		errData, err := io.ReadAll(stream)
		if err != nil {
			return fmt.Errorf("failed reading error data (code %d): %w", int(code[0]), err)
		}

		return fmt.Errorf("received error response (code %d): %s", int(code[0]), string(errData))
	}

	if err = r.cfg.Encoder.DecodeWithMaxLength(stream, data); err != nil {
		return fmt.Errorf("read request data %T: %w", data, err)
	}

	if err = stream.CloseRead(); err != nil {
		return fmt.Errorf("failed to close reading side of stream: %w", err)
	}

	return nil
}

func (r *ReqResp) writeRequest(ctx context.Context, stream network.Stream, data ssz.Marshaler) (err error) {
	if err = stream.SetWriteDeadline(time.Now().Add(r.cfg.WriteTimeout)); err != nil {
		return fmt.Errorf("failed setting write deadline on stream: %w", err)
	}

	if _, err = r.cfg.Encoder.EncodeWithMaxLength(stream, data); err != nil {
		return fmt.Errorf("read sequence number: %w", err)
	}

	if err = stream.CloseWrite(); err != nil {
		return fmt.Errorf("failed to close writing side of stream: %w", err)
	}

	return nil
}

// writeResponse differs from writeRequest in prefixing the payload data with
// a response code byte.
func (r *ReqResp) writeResponse(ctx context.Context, stream network.Stream, data ssz.Marshaler) (err error) {
	if err = stream.SetWriteDeadline(time.Now().Add(r.cfg.WriteTimeout)); err != nil {
		return fmt.Errorf("failed setting write deadline on stream: %w", err)
	}

	if _, err := stream.Write([]byte{0}); err != nil { // success response
		return fmt.Errorf("write success response code: %w", err)
	}

	if _, err = r.cfg.Encoder.EncodeWithMaxLength(stream, data); err != nil {
		return fmt.Errorf("read sequence number: %w", err)
	}

	if err = stream.CloseWrite(); err != nil {
		return fmt.Errorf("failed to close writing side of stream: %w", err)
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
	req := primitives.SSZUint64(0)
	if err := r.readRequest(ctx, stream, &req); err != nil {
		return fmt.Errorf("read sequence number: %w", err)
	}

	sq := primitives.SSZUint64(uint64(23))
	if err := r.writeResponse(ctx, stream, &sq); err != nil {
		r.cfg.Logger.Error("write sequence number", err)
	}
	return stream.Close()
}

func (r *ReqResp) goodbyeHandler(ctx context.Context, stream network.Stream) error {
	req := primitives.SSZUint64(0)
	if err := r.readRequest(ctx, stream, &req); err != nil {
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

func ParseGoodByeReason(num p2ptypes.RPCGoodbyeCode) string {
	reason, ok := p2ptypes.GoodbyeCodeMessages[num]
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
