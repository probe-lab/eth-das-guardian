package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/p2p/enode"
)

var (
	NUMBER_OF_CUSTODY_GROUPS = uint64(128)
	UINT256_MAX              = big.NewInt(0).SetBytes(hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"))
)

func hex2Bytes(str string) []byte {
	h, _ := hex.DecodeString(str)
	return h
}

// https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/p2p-interface.md#custody-group-count
type CgcEntry uint64

func (c CgcEntry) ENRKey() string {
	return "cgc"
}

func GetCustodyFromEnr(ethNode *enode.Node) (custody uint64, err error) {
	enr := ethNode.Record()

	var custodyEntry CgcEntry
	err = enr.Load(&custodyEntry)
	if err != nil {
		return uint64(0), err
	}
	return uint64(custodyEntry), nil
}

// https://github.com/ethereum/consensus-specs/blob/dev/specs/fulu/das-core.md#get_custody_groups
func GetCustodyIdxsForNode(nodeID enode.ID, custody int) []uint64 {
	custodyIdxs := make([]uint64, 0)
	currentID := big.NewInt(0).SetBytes(nodeID.Bytes())

	for len(custodyIdxs) < custody {
		hash := sha256.Sum256(currentID.Bytes())

		custodyG := uint64(bytes_to_uint64(hash[:8])) % uint64(NUMBER_OF_CUSTODY_GROUPS)

		// check if the custodyG isn't already at the group
		isNew := true
		for _, cg := range custodyIdxs {
			if custodyG == cg {
				isNew = false
				break
			}
		}
		if isNew {
			custodyIdxs = append(custodyIdxs, custodyG)
		}
		if currentID == UINT256_MAX {
			currentID = big.NewInt(0)
		} else {
			currentID.Add(currentID, big.NewInt(1))
		}
	}
	sort.Slice(custodyIdxs, func(i, j int) bool { return custodyIdxs[i] < custodyIdxs[j] })
	return custodyIdxs
}

func bytes_to_uint64(b []byte) uint64 {
	return binary.LittleEndian.Uint64(b)
}
