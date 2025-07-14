package dasguardian

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/pkg/errors"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const PeerDAScolumns = 128

func (r *ReqResp) EnsureConnectionToPeer(ctx context.Context, pid peer.ID) error {
	constatus := r.host.Network().Connectedness(pid)
	if constatus != network.Connected {
		return nil
	} else {
		return r.host.Connect(ctx, r.host.Peerstore().PeerInfo(pid))
	}
}

func (r *ReqResp) Ping(ctx context.Context, pid peer.ID) (err error) {
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return err
	}
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCPingTopicV1))
	if err != nil {
		return fmt.Errorf("new %s stream to peer %s: %w", RPCPingTopicV1, pid, err)
	}
	defer stream.Reset()

	req := uint64(1)
	if err := r.writeRequest(stream, &req); err != nil {
		return fmt.Errorf("write ping request: %w", err)
	}

	// read and decode status response
	resp := uint64(0)
	if err := r.readResponse(stream, &resp); err != nil {
		return fmt.Errorf("read ping response: %w", err)
	}

	// we have the data that we want, so ignore error here
	_ = stream.Close() // (both sides should actually be already closed)

	return nil
}

func (r *ReqResp) GoodBye(ctx context.Context, pid peer.ID) (err error) {
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCGoodByeTopicV1))
	if err != nil {
		return fmt.Errorf("new %s stream to peer %s: %w", RPCGoodByeTopicV1, pid, err)
	}
	defer stream.Reset()

	req := uint64(1)
	if err := r.writeRequest(stream, &req); err != nil {
		return fmt.Errorf("write goodbye request: %w", err)
	}

	// read and decode status response
	resp := uint64(0)
	if err := r.readResponse(stream, resp); err != nil {
		return fmt.Errorf("read goodbye response: %w", err)
	}

	// we have the data that we want, so ignore error here
	_ = stream.Close() // (both sides should actually be already closed)

	return nil
}

func (r *ReqResp) StatusV1(ctx context.Context, pid peer.ID, st *StatusV1) (status *StatusV1, err error) {
	if isNill(st) {
		return nil, fmt.Errorf("the given local-status-v1 is a nil pointer")
	}
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return nil, err
	}
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCStatusTopicV1))
	if err != nil {
		return nil, fmt.Errorf("new stream to peer %s: %w", pid, err)
	}
	defer stream.Reset()

	if err := r.writeRequest(stream, st); err != nil {
		return nil, fmt.Errorf("write status-v1 request: %w", err)
	}

	// read and decode status response
	resp := &StatusV1{}
	if err := r.readResponse(stream, resp); err != nil {
		return nil, fmt.Errorf("read status-v1 response: %w", err)
	}

	// we have the data that we want, so ignore error here
	_ = stream.Close() // (both sides should actually be already closed)

	return resp, nil
}

func (r *ReqResp) StatusV2(ctx context.Context, pid peer.ID, st *StatusV2) (status *StatusV2, err error) {
	if isNill(st) {
		return nil, fmt.Errorf("the given local-status-v2 is a nil pointer")
	}
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return nil, errors.Wrap(err, "connection wasn't stablished when requesting status-v2")
	}
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCStatusTopicV2))
	if err != nil {
		return nil, fmt.Errorf("new stream to peer %s: %w", pid, err)
	}
	defer stream.Reset()

	if err := r.writeRequest(stream, st); err != nil {
		return nil, fmt.Errorf("write status-v2 request: %w", err)
	}

	// read and decode status response
	resp := &StatusV2{}
	if err := r.readResponse(stream, resp); err != nil {
		return nil, fmt.Errorf("read status-v2 response: %w", err)
	}

	// we have the data that we want, so ignore error here
	_ = stream.Close() // (both sides should actually be already closed)

	return resp, nil
}

func (r *ReqResp) MetaDataV2(ctx context.Context, pid peer.ID, md *MetaDataV2) (resp *MetaDataV2, err error) {
	if isNill(md) {
		return nil, fmt.Errorf("the given local-metadata-v2 is a nil pointer")
	}
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return nil, err
	}
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCMetaDataTopicV2))
	if err != nil {
		return resp, fmt.Errorf("new %s stream to peer %s: %w", RPCMetaDataTopicV2, pid, err)
	}
	defer stream.Reset()

	if err := r.writeRequest(stream, md); err != nil {
		return nil, fmt.Errorf("write metadata-v2 request: %w", err)
	}

	// read and decode status response
	resp = &MetaDataV2{}
	if err := r.readResponse(stream, resp); err != nil {
		return nil, fmt.Errorf("read metadata-v2 response: %w", err)
	}

	// we have the data that we want, so ignore error here
	_ = stream.Close() // (both sides should actually be already closed)

	return resp, nil
}

func (r *ReqResp) MetaDataV3(ctx context.Context, pid peer.ID, md *MetaDataV3) (resp *MetaDataV3, err error) {
	if isNill(md) {
		return nil, fmt.Errorf("the given local-metadata-v3 is a nil pointer")
	}
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return nil, err
	}
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCMetaDataTopicV3))
	if err != nil {
		return resp, fmt.Errorf("new %s stream to peer %s: %w", RPCMetaDataTopicV3, pid, err)
	}
	defer stream.Reset()

	if err := r.writeRequest(stream, md); err != nil {
		return nil, fmt.Errorf("write metadata-v3 request: %w", err)
	}

	// read and decode status response
	resp = &MetaDataV3{}
	if err := r.readResponse(stream, resp); err != nil {
		return nil, fmt.Errorf("read metadata-v3 response: %w", err)
	}

	// we have the data that we want, so ignore error here
	_ = stream.Close() // (both sides should actually be already closed)

	return resp, nil
}

// block requests
func (r *ReqResp) RawBlocksByRangeV2(ctx context.Context, pid peer.ID, startSlot, finishSlot int64) ([]*deneb.SignedBeaconBlock, error) {
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return nil, err
	}
	var err error

	blocks := make([]*deneb.SignedBeaconBlock, 0)
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCBlocksByRangeTopicV2))
	if err != nil {
		return blocks, fmt.Errorf("new %s stream to peer %s: %w", RPCMetaDataTopicV2, pid, err)
	}
	defer stream.Close()
	defer stream.Reset()

	req := &BeaconBlocksByRangeRequestV1{
		StartSlot: uint64(startSlot),
		Count:     uint64(finishSlot - startSlot),
		Step:      1,
	}
	if err := r.writeRequest(stream, req); err != nil {
		return blocks, fmt.Errorf("write block_by_range request: %w", err)
	}

	// read and decode status response
	for i := uint64(0); ; i++ {
		isFirstChunk := i == 0
		block := &deneb.SignedBeaconBlock{}
		err := r.readChunkedResponse(stream, block, isFirstChunk, r.cfg.ForkDigest(uint64(startSlot)+i))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading block_by_range request: %w", err)
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

func (r *ReqResp) BlocksByRangeV2(ctx context.Context, pid peer.ID, startSlot, finishSlot uint64) (time.Duration, []*deneb.SignedBeaconBlock, error) {
	blocks := make([]*deneb.SignedBeaconBlock, 0)
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return time.Duration(0), blocks, err
	}
	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCBlocksByRangeTopicV2))
	if err != nil {
		return time.Duration(0), blocks, fmt.Errorf("new %s stream to peer %s: %w", RPCMetaDataTopicV2, pid, err)
	}
	defer stream.Close()
	defer stream.Reset()

	req := &BeaconBlocksByRangeRequestV1{
		StartSlot: startSlot,
		Count:     finishSlot - startSlot,
		Step:      1,
	}
	if err := r.writeRequest(stream, req); err != nil {
		return time.Duration(0), blocks, fmt.Errorf("write block_by_range request: %w", err)
	}

	tStart := time.Now()
	// read and decode status response
	for i := uint64(0); ; i++ {
		isFirstChunk := i == 0
		block := &deneb.SignedBeaconBlock{}
		err := r.readChunkedResponse(stream, block, isFirstChunk, r.cfg.ForkDigest(startSlot+i))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return time.Duration(0), nil, fmt.Errorf("reading block_by_range request: %w", err)
		}
		blocks = append(blocks, block)
	}
	opDuration := time.Since(tStart)
	return opDuration, blocks, nil
}

// -- Data column requests --
// https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/p2p-interface.md#datacolumnsidecarsbyrange-v1
func (r *ReqResp) DataColumnByRangeV1(ctx context.Context, pid peer.ID, slot uint64, columnIdxs []uint64) (time.Duration, []*DataColumnSidecarV1, error) {
	dataColumns := make([]*DataColumnSidecarV1, 0)
	if err := r.EnsureConnectionToPeer(ctx, pid); err != nil {
		return time.Duration(0), dataColumns, err
	}
	chunks := uint64(1 * len(columnIdxs) * PeerDAScolumns)

	stream, err := r.host.NewStream(ctx, pid, protocol.ID(RPCDataColumnSidecarsByRangeTopicV1))
	if err != nil {
		return time.Duration(0), dataColumns, fmt.Errorf("new %s stream to peer %s: %w", RPCMetaDataTopicV2, pid, err)
	}
	defer stream.Close()
	defer stream.Reset()

	req := &DataColumnSidecarsByRangeRequestV1{
		StartSlot: slot,
		Count:     uint64(1),
		Columns:   columnIdxs,
	}
	if err := r.writeRequest(stream, req); err != nil {
		return time.Duration(0), dataColumns, fmt.Errorf("write data_columns_by_range request: %w", err)
	}

	tStart := time.Now()
	// read and decode status response

	for i := uint64(0); ; /* no stop condition */ i++ {
		dataCol := &DataColumnSidecarV1{}
		err := r.readChunkedResponse(stream, dataCol, false, r.cfg.ForkDigest(slot))
		if errors.Is(err, io.EOF) {
			// End of stream.
			break
		}

		if err != nil {
			return time.Duration(0), dataColumns, errors.Wrap(err, "read chunked data column sidecar")
		}

		if i >= chunks {
			// The response MUST contain no more than `reqCount` blocks.
			// (`reqCount` is already capped by `maxRequestDataColumnSideCar`.)
			return time.Duration(0), dataColumns, errors.New("invalid - response contains more data column sidecars than requested")
		}

		dataColumns = append(dataColumns, dataCol)
	}
	opDuration := time.Since(tStart)
	return opDuration, dataColumns, nil
}
