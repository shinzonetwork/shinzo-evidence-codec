package rule

import (
	"crypto/sha256"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"regexp"

	"github.com/ethereum/go-ethereum/common"

	"github.com/shinzonetwork/shinzo-evidence-codec/evm"
	"github.com/shinzonetwork/shinzo-evidence-codec/statement"
	"github.com/shinzonetwork/shinzo-evidence-codec/trust"
)

// eip155ID is an EIP-155 chain ID in CAIP-2 form, the reference in base 10 without leading zeros.
var eip155ID = regexp.MustCompile(`^eip155:[1-9][0-9]*$`)

// evmAssetID is a contract address in 40 lower-case hex digits, the form a statement's claims carry.
var evmAssetID = regexp.MustCompile(`^[0-9a-f]{40}$`)

var errHeaderMismatch = errors.New("header does not match the statement")

type evmChain struct {
	id    string
	slots map[string]common.Hash // supply slot by asset ID
}

type evmAssetSettings struct {
	SupplySlot *evm.StorageKey `json:"supplySlot"`
}

func newEVM(c trust.Chain) (evmChain, error) {
	if !eip155ID.MatchString(c.ID) {
		return evmChain{}, fmt.Errorf("%w: chain %q is not eip155 with a decimal reference", ErrSettings, c.ID)
	}
	if len(c.Settings) > 0 {
		return evmChain{}, fmt.Errorf("%w: evm has no chain settings", ErrSettings)
	}
	e := evmChain{id: c.ID, slots: make(map[string]common.Hash, len(c.Assets))}
	for _, a := range c.Assets {
		if !evmAssetID.MatchString(a.ID) {
			return evmChain{}, fmt.Errorf("%w: asset %q is not 40 lower-case hex digits", ErrSettings, a.ID)
		}
		var s evmAssetSettings
		if err := jsonv2.Unmarshal(a.Settings, &s, jsonv2.RejectUnknownMembers(true)); err != nil {
			return evmChain{}, fmt.Errorf("%w: asset %s: %w", ErrSettings, a.ID, err)
		}
		if s.SupplySlot == nil {
			return evmChain{}, fmt.Errorf("%w: asset %s has no supplySlot", ErrSettings, a.ID)
		}
		e.slots[a.ID] = common.Hash(*s.SupplySlot)
	}
	return e, nil
}

func (e evmChain) header(raw []byte, s statement.Statement) (blockChecks, error) {
	h, err := evm.HeaderFromRaw(raw)
	if err != nil {
		return nil, err
	}
	ms, err := evm.BlockTime(e.id, h)
	if err != nil {
		return nil, err
	}
	if h.Hash.Hex() != s.Hash || h.ParentHash.Hex() != s.ParentHash || h.Number != s.Number ||
		s.ParentNumber+1 != s.Number || ms != s.Timestamp {
		return nil, errHeaderMismatch
	}
	return evmBlock{header: h, slots: e.slots}, nil
}

type evmBlock struct {
	header evm.Header
	slots  map[string]common.Hash
}

func (b evmBlock) records(_ trust.Asset, records, proof []byte) (uint64, [sha256.Size]byte, error) {
	decoded, root, err := evm.DecodeRecords(records)
	if err != nil {
		return 0, root, err
	}
	if err := evm.VerifyRecords(b.header.ReceiptsRoot, b.header.TransactionsRoot, decoded, proof); err != nil {
		return 0, root, err
	}
	return uint64(len(decoded)), root, nil
}

func (b evmBlock) capture(asset trust.Asset, proof []byte) (string, error) {
	value, err := evm.VerifyStateCapture(b.header.StateRoot, common.HexToAddress(asset.ID), b.slots[asset.ID], proof)
	if err != nil {
		return "", err
	}
	return value.String(), nil
}
