package evm

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// Errors returned by HeaderFromRaw and BlockTime.
var (
	ErrHeaderShort  = errors.New("header has too few fields")
	ErrMilliseconds = errors.New("mixHash milliseconds are 1000 or more")
)

// Header is the part of an EVM block header the agreement rule reads.
type Header struct {
	Hash             common.Hash // keccak256 of the raw header
	ParentHash       common.Hash
	StateRoot        common.Hash
	TransactionsRoot common.Hash
	ReceiptsRoot     common.Hash
	Number           uint64
	Time             uint64 // seconds
	MixDigest        common.Hash
}

// Positions in the RLP header list, in go-ethereum's types.Header order (core/types/block.go:68-83 @ v1.17.10).
const (
	parentHashField       = 0
	stateRootField        = 3
	transactionsRootField = 4
	receiptsRootField     = 5
	numberField           = 8
	timeField             = 11
	mixDigestField        = 13
)

const (
	bscMainnet            = "eip155:56"
	millisecondsPerSecond = 1000
)

// HeaderFromRaw decodes an RLP block header. Fields are read by position, so a field that a later fork appends does
// not break decoding.
func HeaderFromRaw(raw []byte) (Header, error) {
	var fields []rlp.RawValue
	if err := rlp.DecodeBytes(raw, &fields); err != nil {
		return Header{}, fmt.Errorf("decode header: %w", err)
	}
	if len(fields) <= mixDigestField {
		return Header{}, fmt.Errorf("%w: %d", ErrHeaderShort, len(fields))
	}
	h := Header{Hash: crypto.Keccak256Hash(raw)}
	for _, f := range []struct {
		position int
		into     any
	}{
		{parentHashField, &h.ParentHash},
		{stateRootField, &h.StateRoot},
		{transactionsRootField, &h.TransactionsRoot},
		{receiptsRootField, &h.ReceiptsRoot},
		{numberField, &h.Number},
		{timeField, &h.Time},
		{mixDigestField, &h.MixDigest},
	} {
		if err := rlp.DecodeBytes(fields[f.position], f.into); err != nil {
			return Header{}, fmt.Errorf("header field %d: %w", f.position, err)
		}
	}
	return h, nil
}

// BlockTime returns the block's time in milliseconds. BSC keeps the milliseconds past Time in the low 64 bits of
// mixHash, and its consensus refuses 1000 or more (core/types/block.go:167-173 and consensus/parlia/parlia.go:628-637
// @ bsc v1.8.2). Other chains use mixHash for something else.
func BlockTime(chain string, h Header) (uint64, error) {
	ms := h.Time * millisecondsPerSecond
	if chain != bscMainnet {
		return ms, nil
	}
	extra := new(uint256.Int).SetBytes32(h.MixDigest[:]).Uint64()
	if extra >= millisecondsPerSecond {
		return 0, fmt.Errorf("%w: %d", ErrMilliseconds, extra)
	}
	return ms + extra, nil
}
