package evm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/shinzonetwork/shinzo-evidence-codec/merkle"
)

// blockSize puts the last indices past 127, where the RLP key of an index grows to two bytes.
const blockSize = 130

var provenIndices = []uint64{0, 1, 2, 127, 128, 129}

// The expected bytes are written by hand, so a layout mistake shared by EncodeRecords and DecodeRecords still fails.
func TestEncodeRecords(t *testing.T) {
	t.Parallel()
	records := []Record{
		{Index: 0, Receipt: []byte{0x01}, Transaction: []byte{0x02, 0x03}},
		{Index: 5, Receipt: []byte{0xaa}, Transaction: []byte{0xbb, 0xcc}},
	}
	first, second := hexBytes(t, "c58001820203"), hexBytes(t, "c60581aa82bbcc")
	want := append(append([]byte{0xcd}, first...), second...)
	wantRoot := merkle.Root([][]byte{first, second})

	encoded, root, err := EncodeRecords(records)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) || root != wantRoot {
		t.Fatalf("EncodeRecords = %x, %x\nwant %x, %x", encoded, root, want, wantRoot)
	}
	decoded, root, err := DecodeRecords(want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, records) || root != wantRoot {
		t.Fatalf("DecodeRecords = %+v, %x\nwant %+v, %x", decoded, root, records, wantRoot)
	}
}

func TestEncodeRecordsRejects(t *testing.T) {
	t.Parallel()
	a, b := Record{Index: 0, Receipt: []byte{1}, Transaction: []byte{2}}, Record{Index: 5, Receipt: []byte{3}, Transaction: []byte{4}}
	for name, records := range map[string][]Record{"out of order": {b, a}, "repeated": {a, a}} {
		if _, _, err := EncodeRecords(records); !errors.Is(err, ErrUnsorted) {
			t.Errorf("%s: EncodeRecords = %v, want %v", name, err, ErrUnsorted)
		}
	}
}

func TestDecodeRecordsRejects(t *testing.T) {
	t.Parallel()
	for name, encoded := range map[string]string{
		"out of order": "cd" + "c60581aa82bbcc" + "c58001820203",
		"repeated":     "cc" + "c58001820203" + "c58001820203",
	} {
		if _, _, err := DecodeRecords(hexBytes(t, encoded)); !errors.Is(err, ErrUnsorted) {
			t.Errorf("%s: DecodeRecords = %v, want %v", name, err, ErrUnsorted)
		}
	}
}

// types.DeriveSha computes the roots the way a block header does, apart from listTrie.
func TestVerifyRecords(t *testing.T) {
	t.Parallel()
	receipts, transactions := testBlock(blockSize)
	proof, err := BuildProof(receipts, transactions, provenIndices)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecords(receiptsRoot(receipts), transactionsRoot(transactions), testRecords(t, receipts, transactions), proof); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRecordsRejects(t *testing.T) {
	t.Parallel()
	receipts, transactions := testBlock(blockSize)
	proof, err := BuildProof(receipts, transactions, provenIndices)
	if err != nil {
		t.Fatal(err)
	}
	var nodes proofNodes
	if err := rlp.DecodeBytes(proof, &nodes); err != nil {
		t.Fatal(err)
	}
	nodes.Receipts = nodes.Receipts[:len(nodes.Receipts)-1]
	droppedNode, err := rlp.EncodeToBytes(nodes)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		alter   func(records []Record) []Record
		proof   []byte
		wantErr error
	}{
		{"receipts swapped", func(r []Record) []Record { r[0].Receipt, r[1].Receipt = r[1].Receipt, r[0].Receipt; return r }, proof, ErrMismatch},
		{"transactions swapped", func(r []Record) []Record {
			r[0].Transaction, r[1].Transaction = r[1].Transaction, r[0].Transaction
			return r
		}, proof, ErrMismatch},
		{"wrong index", func(r []Record) []Record { r[0].Index = r[2].Index; return r }, proof, ErrMismatch},
		{"node dropped", func(r []Record) []Record { return r }, droppedNode, ErrProof},
		{
			"empty position", func([]Record) []Record { return []Record{{Index: blockSize}} },
			absenceProof(t, receipts, transactions, blockSize), ErrMismatch,
		},
	}
	for _, tc := range cases {
		records := tc.alter(testRecords(t, receipts, transactions))
		err := VerifyRecords(receiptsRoot(receipts), transactionsRoot(transactions), records, tc.proof)
		if !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: VerifyRecords = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

// The expected proof is built by hand from the trie layout, so it pins the list order, the node order and the
// removal of the repeated root.
func TestBuildProof(t *testing.T) {
	t.Parallel()
	receipts, transactions := testBlock(2)
	receiptNodes, transactionNodes := twoItemProof(t, receipts), twoItemProof(t, transactions)
	if crypto.Keccak256Hash(receiptNodes[0]) != receiptsRoot(receipts) ||
		crypto.Keccak256Hash(transactionNodes[0]) != transactionsRoot(transactions) {
		t.Fatal("the hand-built tries do not have the consensus roots")
	}
	want, err := rlp.EncodeToBytes([][][]byte{receiptNodes, transactionNodes})
	if err != nil {
		t.Fatal(err)
	}
	got, err := BuildProof(receipts, transactions, []uint64{0, 1})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("BuildProof =\n%x\nwant\n%x", got, want)
	}
}

func TestBuildProofRejects(t *testing.T) {
	t.Parallel()
	receipts, transactions := testBlock(blockSize)
	cases := []struct {
		name    string
		indices []uint64
		wantErr error
	}{
		{"out of order", []uint64{2, 1}, ErrUnsorted},
		{"repeated", []uint64{1, 1}, ErrUnsorted},
		{"past the last item", []uint64{blockSize}, ErrIndexOutOfRange},
	}
	for _, tc := range cases {
		if _, err := BuildProof(receipts, transactions, tc.indices); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: BuildProof = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
}

// testBlock returns n distinct legacy, access-list and dynamic-fee transactions with a receipt each.
func testBlock(n int) (types.Receipts, types.Transactions) {
	to := common.HexToAddress("0x01")
	receipts := make(types.Receipts, n)
	transactions := make(types.Transactions, n)
	for i := range n {
		nonce := uint64(i)
		var data types.TxData
		switch i % 3 {
		case 0:
			data = &types.LegacyTx{Nonce: nonce, To: &to, Gas: 21000, GasPrice: big.NewInt(1)}
		case 1:
			data = &types.AccessListTx{ChainID: big.NewInt(1), Nonce: nonce, To: &to, Gas: 21000, GasPrice: big.NewInt(1)}
		default:
			data = &types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: nonce, To: &to, Gas: 21000, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2)}
		}
		transactions[i] = types.NewTx(data)
		receipts[i] = &types.Receipt{
			Type:              transactions[i].Type(),
			Status:            types.ReceiptStatusSuccessful,
			CumulativeGasUsed: 21000 * (nonce + 1),
			Logs:              []*types.Log{{Address: to, Data: []byte{byte(i)}}},
		}
	}
	return receipts, transactions
}

// testRecords returns the records at provenIndices, encoded with MarshalBinary as a generator would.
func testRecords(t *testing.T, receipts types.Receipts, transactions types.Transactions) []Record {
	t.Helper()
	records := make([]Record, len(provenIndices))
	for i, index := range provenIndices {
		receipt, err := receipts[index].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		transaction, err := transactions[index].MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		records[i] = Record{Index: index, Receipt: receipt, Transaction: transaction}
	}
	return records
}

// twoItemProof returns the proof of both items of a two-item list, proven in index order. The keys RLP(0) = 0x80
// and RLP(1) = 0x01 differ in their first nibble, so the root is a branch holding the leaf for index 1 under nibble 0
// and the leaf for index 0 under nibble 8. Each leaf key is the one nibble left, in compact form: 0x30 | nibble
// (hexToCompact, trie/encoding.go:37-52 @ go-ethereum v1.17.10).
func twoItemProof(t *testing.T, list types.DerivableList) [][]byte {
	t.Helper()
	leaf := func(key byte, index int) []byte {
		var value bytes.Buffer
		list.EncodeIndex(index, &value)
		node, err := rlp.EncodeToBytes([][]byte{{key}, value.Bytes()})
		if err != nil {
			t.Fatal(err)
		}
		return node
	}
	leaf0, leaf1 := leaf(0x30, 0), leaf(0x31, 1)
	children := make([][]byte, 17)
	children[0], children[8] = crypto.Keccak256(leaf1), crypto.Keccak256(leaf0)
	branch, err := rlp.EncodeToBytes(children)
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{branch, leaf0, leaf1}
}

// absenceProof returns a proof that both tries are empty at index.
func absenceProof(t *testing.T, receipts, transactions types.DerivableList, index uint64) []byte {
	t.Helper()
	var nodes proofNodes
	for _, side := range []struct {
		list  types.DerivableList
		nodes *[][]byte
	}{{receipts, &nodes.Receipts}, {transactions, &nodes.Transactions}} {
		tr, err := listTrie(side.list)
		if err != nil {
			t.Fatal(err)
		}
		set := proofSet(nil)
		if err := tr.Prove(rlp.AppendUint64(nil, index), set); err != nil {
			t.Fatal(err)
		}
		*side.nodes = set.List()
	}
	proof, err := rlp.EncodeToBytes(nodes)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func receiptsRoot(receipts types.Receipts) common.Hash {
	return types.DeriveSha(receipts, trie.NewStackTrie(nil))
}

func transactionsRoot(transactions types.Transactions) common.Hash {
	return types.DeriveSha(transactions, trie.NewStackTrie(nil))
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
