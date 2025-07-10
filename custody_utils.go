package dasguardian

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"sort"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/holiman/uint256"
	errors "github.com/pkg/errors"
)

var (
	NUMBER_OF_CUSTODY_GROUPS = uint64(128)
	UINT256_MAX              = &uint256.Int{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64}
)

// https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/p2p-interface.md#custody-group-count
type CgcEntry uint64

func (c CgcEntry) ENRKey() string {
	return "cgc"
}

func GetCustodyFromEnr(ethNode *enode.Node) (uint64, error) {
	enr := ethNode.Record()

	var custodyEntry CgcEntry
	err := enr.Load(&custodyEntry)
	if err != nil {
		return uint64(0), errors.Wrap(err, "unable to get custody from enr")
	}
	return uint64(custodyEntry), nil
}

// attnets
type AttnetsEntry []byte

func (c AttnetsEntry) ENRKey() string { return "attnets" }

func GetAttnetsFromEnr(ethNode *enode.Node) string {
	enr := ethNode.Record()

	var attnetsEntry AttnetsEntry
	err := enr.Load(&attnetsEntry)
	if err != nil {
		return "no-attnets"
	}
	return "0x" + hex.EncodeToString(attnetsEntry)
}

// syncnets
type SyncnetsEntry []byte

func (c SyncnetsEntry) ENRKey() string { return "syncnets" }

func GetSyncnetsFromEnr(ethNode *enode.Node) string {
	enr := ethNode.Record()

	var syncnetsEntry SyncnetsEntry
	err := enr.Load(&syncnetsEntry)
	if err != nil {
		return "no-syncnets"
	}
	return "0x" + hex.EncodeToString(syncnetsEntry)
}

// Mainly from: prysm/beacon-chain/core/peerdas/helpers.go
var (
	// Custom errors
	errCustodySubnetCountTooLarge = errors.New("custody subnet count larger than data column sidecar subnet count")
	errCustodyColumnCountZero     = errors.New("custody column count is zero")

	// maxUint256 is the maximum value of a uint256.
	maxUint256 = &uint256.Int{math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64}
)

func CustodyColumnSubnets(nodeId enode.ID, custodySubnetCount uint64, dataColumnSidecarSubnetCount uint64) (map[uint64]bool, error) {
	// Check if the custody subnet count is larger than the data column sidecar subnet count.
	if custodySubnetCount > dataColumnSidecarSubnetCount {
		return nil, errCustodySubnetCountTooLarge
	}
	if dataColumnSidecarSubnetCount == 0 {
		return nil, errCustodyColumnCountZero
	}

	// First, compute the subnet IDs that the node should participate in.
	subnetIds := make(map[uint64]bool, custodySubnetCount)

	one := uint256.NewInt(1)

	for currentId := new(uint256.Int).SetBytes(nodeId.Bytes()); uint64(len(subnetIds)) < custodySubnetCount; currentId.Add(currentId, one) {
		// Convert to big endian bytes.
		currentIdBytesBigEndian := currentId.Bytes32()

		// Convert to little endian.
		currentIdBytesLittleEndian := reverseByteOrder(currentIdBytesBigEndian[:])

		// Hash the result.
		hashedCurrentId := hash(currentIdBytesLittleEndian)

		// Get the subnet ID.
		subnetId := binary.LittleEndian.Uint64(hashedCurrentId[:8]) % dataColumnSidecarSubnetCount

		// Add the subnet to the map.
		subnetIds[subnetId] = true

		// Overflow prevention.
		if currentId.Cmp(maxUint256) == 0 {
			currentId = uint256.NewInt(0)
		}
	}

	return subnetIds, nil
}

// CustodyColumns computes the columns the node should custody.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7594/das-core.md#helper-functions
func CustodyColumns(nodeId enode.ID, custodySubnetCount uint64, numberOfColumns uint64, dataColumnSidecarSubnetCount uint64) (map[uint64]bool, error) {
	// Compute the custodied subnets.
	subnetIds, err := CustodyColumnSubnets(nodeId, custodySubnetCount, dataColumnSidecarSubnetCount)
	if err != nil {
		return nil, errors.Wrap(err, "custody subnets")
	}

	columnsPerSubnet := numberOfColumns / dataColumnSidecarSubnetCount

	// Knowing the subnet ID and the number of columns per subnet, select all the columns the node should custody.
	// Columns belonging to the same subnet are contiguous.
	columnIndices := make(map[uint64]bool, custodySubnetCount*columnsPerSubnet)
	for i := uint64(0); i < columnsPerSubnet; i++ {
		for subnetId := range subnetIds {
			columnIndex := dataColumnSidecarSubnetCount*i + subnetId
			columnIndices[columnIndex] = true
		}
	}

	return columnIndices, nil
}

func CustodyColumnsSlice(nodeId enode.ID, custodySubnetCount uint64, numberOfColumns uint64, dataColumnSidecarSubnetCount uint64) ([]uint64, error) {
	columns, err := CustodyColumns(nodeId, custodySubnetCount, numberOfColumns, dataColumnSidecarSubnetCount)
	if err != nil {
		return nil, err
	}
	columnsSlice := make([]uint64, 0, len(columns))
	for column := range columns {
		columnsSlice = append(columnsSlice, column)
	}

	sort.Slice(columnsSlice, func(i, j int) bool {
		return columnsSlice[i] < columnsSlice[j]
	})

	return columnsSlice, nil
}

func CustodyColumnSubnetsSlice(nodeId enode.ID, custodySubnetCount uint64, dataColumnSidecarSubnetCount uint64) ([]uint64, error) {
	subnets, err := CustodyColumnSubnets(nodeId, custodySubnetCount, dataColumnSidecarSubnetCount)
	if err != nil {
		return nil, err
	}
	subnetsSlice := make([]uint64, 0, len(subnets))
	for subnet := range subnets {
		subnetsSlice = append(subnetsSlice, subnet)
	}
	sort.Slice(subnetsSlice, func(i, j int) bool {
		return subnetsSlice[i] < subnetsSlice[j]
	})

	return subnetsSlice, nil
}
