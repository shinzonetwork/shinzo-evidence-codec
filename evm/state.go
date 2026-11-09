package evm

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// Errors returned by VerifyStateCapture, besides ErrProof.
var (
	ErrAccountNotInState = errors.New("account does not exist in the proven state")
	ErrSlotNotProven     = errors.New("proof has no entry for the slot")
)

// AccountProof is an eth_getProof answer (EIP-1186) for one account and some of its storage slots.
type AccountProof struct {
	AccountProof []hexutil.Bytes `json:"accountProof"`
	StorageProof []StorageProof  `json:"storageProof"`
}

// StorageProof is the proof of one storage slot within an AccountProof.
type StorageProof struct {
	Key   StorageKey      `json:"key"`
	Proof []hexutil.Bytes `json:"proof"`
}

// StorageKey is a slot as eth_getProof echoes it: 32 bytes when the request gave 32 bytes, otherwise a quantity such as
// "0x35" (internal/ethapi/api.go:424-433 @ go-ethereum v1.17.10).
type StorageKey common.Hash

// UnmarshalJSON reads a JSON string with ParseStorageKey.
func (k *StorageKey) UnmarshalJSON(input []byte) error {
	var s string
	if err := json.Unmarshal(input, &s); err != nil {
		return err
	}
	key, err := ParseStorageKey(s)
	if err != nil {
		return err
	}
	*k = key
	return nil
}

// ParseStorageKey accepts a 0x-prefixed hex string of up to 32 bytes and left-pads it.
func ParseStorageKey(s string) (StorageKey, error) {
	digits, ok := strings.CutPrefix(s, "0x")
	if !ok || digits == "" {
		return StorageKey{}, fmt.Errorf("storage key %q: not a 0x-prefixed hex string", s)
	}
	if len(digits)%2 == 1 {
		digits = "0" + digits
	}
	b, err := hex.DecodeString(digits)
	if err != nil {
		return StorageKey{}, fmt.Errorf("storage key %q: %w", s, err)
	}
	if len(b) > common.HashLength {
		return StorageKey{}, fmt.Errorf("storage key %q: longer than 32 bytes", s)
	}
	return StorageKey(common.BytesToHash(b)), nil
}

// stateProof is the RLP form of a state proof: the account nodes, then each slot with its storage nodes.
type stateProof struct {
	Account [][]byte
	Storage []slotProof
}

type slotProof struct {
	Slot  common.Hash
	Nodes [][]byte
}

// EncodeStateProof returns the state proof for an eth_getProof answer, keeping its node and slot order.
func EncodeStateProof(p AccountProof) ([]byte, error) {
	sp := stateProof{Account: nodeBytes(p.AccountProof), Storage: make([]slotProof, len(p.StorageProof))}
	for i, s := range p.StorageProof {
		sp.Storage[i] = slotProof{Slot: common.Hash(s.Key), Nodes: nodeBytes(s.Proof)}
	}
	return rlp.EncodeToBytes(sp)
}

// VerifyStateCapture checks a proof from EncodeStateProof against stateRoot and returns the value of contract's
// storage slot. The proof's entry for slot supplies only the nodes; a slot absent from storage is proven to hold zero.
func VerifyStateCapture(stateRoot common.Hash, contract common.Address, slot common.Hash, proof []byte) (*big.Int, error) {
	var sp stateProof
	if err := rlp.DecodeBytes(proof, &sp); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProof, err)
	}
	i := slices.IndexFunc(sp.Storage, func(s slotProof) bool { return s.Slot == slot })
	if i < 0 {
		return nil, fmt.Errorf("slot %s: %w", slot, ErrSlotNotProven)
	}
	accountRLP, err := trie.VerifyProof(stateRoot, crypto.Keccak256(contract.Bytes()), proofSet(sp.Account))
	if err != nil {
		return nil, fmt.Errorf("account %s: %w: %w", contract, ErrProof, err)
	}
	if accountRLP == nil {
		return nil, fmt.Errorf("account %s: %w", contract, ErrAccountNotInState)
	}
	var account types.StateAccount
	if err := rlp.DecodeBytes(accountRLP, &account); err != nil {
		return nil, fmt.Errorf("account %s: %w: %w", contract, ErrProof, err)
	}
	// Nodes send no storage nodes for an account with empty storage (internal/ethapi/api.go:413-436 @ go-ethereum v1.17.10).
	if account.Root == types.EmptyRootHash {
		return new(big.Int), nil
	}
	valueRLP, err := trie.VerifyProof(account.Root, crypto.Keccak256(slot.Bytes()), proofSet(sp.Storage[i].Nodes))
	if err != nil {
		return nil, fmt.Errorf("slot %s: %w: %w", slot, ErrProof, err)
	}
	value := new(big.Int)
	if valueRLP == nil {
		return value, nil
	}
	var content []byte
	if err := rlp.DecodeBytes(valueRLP, &content); err != nil {
		return nil, fmt.Errorf("slot %s: %w: %w", slot, ErrProof, err)
	}
	return value.SetBytes(content), nil
}

func nodeBytes(nodes []hexutil.Bytes) [][]byte {
	b := make([][]byte, len(nodes))
	for i, n := range nodes {
		b[i] = n
	}
	return b
}
