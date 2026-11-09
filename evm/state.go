package evm

import (
	"errors"
	"fmt"
	"math/big"
	"slices"

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
	Key   common.Hash     `json:"key"`
	Proof []hexutil.Bytes `json:"proof"`
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
		sp.Storage[i] = slotProof{Slot: s.Key, Nodes: nodeBytes(s.Proof)}
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
