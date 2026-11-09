package rule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"github.com/shinzonetwork/shinzo-evidence-codec/evm"
	"github.com/shinzonetwork/shinzo-evidence-codec/merkle"
	"github.com/shinzonetwork/shinzo-evidence-codec/sig"
	"github.com/shinzonetwork/shinzo-evidence-codec/statement"
)

const (
	height = 1000
	usd1   = "8d0d000ee44948fc98c9b98a4fa4921476f08b0d"
)

// fixture is one EVM block at height with one USD1 record, the documents a host would hold for it, and the statement
// an honest generator signs. The block is synthetic; its stateRoot and the USD1 supply proof are real (Ethereum block
// 26307825), so the capture verifies against real state.
type fixture struct {
	chain     Config
	keys      []*secp256k1.PrivateKey // the first three are listed
	header    types.Header
	statement statement.Statement
	raw       []byte
	docs      Documents // without attestations
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	var state struct {
		StateRoot   common.Hash      `json:"stateRoot"`
		TotalSupply hexutil.Bytes    `json:"ethCallTotalSupply"`
		Proof       evm.AccountProof `json:"proof"`
	}
	b, err := os.ReadFile(filepath.Join("..", "evm", "testdata", "ethereum-usd1-proof.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &state); err != nil {
		t.Fatal(err)
	}
	stateProof, err := evm.EncodeStateProof(state.Proof)
	if err != nil {
		t.Fatal(err)
	}
	supply := new(big.Int).SetBytes(state.TotalSupply).String()

	receipts, transactions := testBlock(3)
	header := &types.Header{
		ParentHash:  common.HexToHash("0x01"),
		UncleHash:   types.EmptyUncleHash,
		Root:        state.StateRoot,
		TxHash:      types.DeriveSha(transactions, trie.NewStackTrie(nil)),
		ReceiptHash: types.DeriveSha(receipts, trie.NewStackTrie(nil)),
		Difficulty:  big.NewInt(0),
		Number:      big.NewInt(height),
		Time:        1_700_000_000,
	}
	records, root := testRecords(t, receipts, transactions, 1)
	proof, err := evm.BuildProof(receipts, transactions, []uint64{1})
	if err != nil {
		t.Fatal(err)
	}

	f := &fixture{
		chain: Config{Chain: "eip155:1", Required: 2, Assets: []Asset{{ID: usd1, SupplySlot: "0x35"}}},
		statement: statement.Statement{
			Chain: "eip155:1", Number: height, ParentNumber: height - 1, Status: statement.StatusFinalized,
			Extractor: "test", Filter: statement.FilterContractLog, Items: 3,
			Claims:   []statement.Claim{{Asset: usd1, Count: 1, Root: root}},
			Captures: []statement.Capture{{Asset: usd1, Value: supply, ProofHash: sha256.Sum256(stateProof)}},
		},
		docs: Documents{
			Evidence: []Evidence{{Asset: usd1, Records: records, Proof: proof}},
			Captures: []Capture{{Asset: usd1, Value: supply, Proof: stateProof}},
		},
	}
	f.setHeader(t, *header, 1_700_000_000_000)
	for i := range 4 {
		seed := sha256.Sum256([]byte{byte(i)})
		f.keys = append(f.keys, secp256k1.PrivKeyFromBytes(seed[:]))
	}
	f.chain.Signers = []string{f.key(0), f.key(1), f.key(2)}
	return f
}

// setHeader makes h the block: its raw header, hash, parent, timestamp in milliseconds, and the documents' block hash.
func (f *fixture) setHeader(t *testing.T, h types.Header, timestamp uint64) {
	t.Helper()
	raw, err := rlp.EncodeToBytes(&h)
	if err != nil {
		t.Fatal(err)
	}
	hash := crypto.Keccak256Hash(raw).Hex()
	f.header, f.raw = h, raw
	f.statement.Hash, f.statement.ParentHash, f.statement.HeaderHash = hash, h.ParentHash.Hex(), sha256.Sum256(raw)
	f.statement.Timestamp = timestamp
	f.docs.Headers = []Header{{Hash: hash, Raw: raw}}
	for i := range f.docs.Evidence {
		f.docs.Evidence[i].BlockHash = hash
	}
	for i := range f.docs.Captures {
		f.docs.Captures[i].BlockHash = hash
	}
}

func (f *fixture) key(i int) string {
	return hex.EncodeToString(f.keys[i].PubKey().SerializeCompressed())
}

// attest returns key i's attestation over s.
func (f *fixture) attest(t *testing.T, i int, s statement.Statement) Attestation {
	t.Helper()
	return sign(t, f.keys[i], s)
}

// sign returns key's attestation over s, signed as defradb signs: DER over the SHA-256 of the statement.
func sign(t *testing.T, key *secp256k1.PrivateKey, s statement.Statement) Attestation {
	t.Helper()
	encoded, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(encoded)
	return Attestation{
		Signer:        hex.EncodeToString(key.PubKey().SerializeCompressed()),
		SignatureType: sig.TypeES256K,
		Signature:     hex.EncodeToString(ecdsa.Sign(key, hash[:]).Serialize()),
		Statement:     encoded,
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		setup       func(t *testing.T, f *fixture) (*Block, []Attestation)
		wantReason  string   // empty when the height is accepted
		wantSigners []int    // the accepted keys
		wantResults []string // one per attestation
	}{
		{
			"two of three agree",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				return &Block{Number: height - 1, Hash: f.statement.ParentHash},
					[]Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			"",
			[]int{0, 1},
			[]string{"", ""},
		},
		{
			"an unlisted signer is ignored",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 3, f.statement), f.attest(t, 1, f.statement)}
			},
			"",
			[]int{0, 1},
			[]string{"", ReasonUnlisted, ""},
		},
		{
			"a bad signature drops its signer",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				other := f.statement
				other.Extractor = "other"
				forged := f.attest(t, 1, other)
				forged.Statement = f.attest(t, 1, f.statement).Statement
				return nil, []Attestation{f.attest(t, 0, f.statement), forged}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonBelowK, ReasonSignature},
		},
		{
			"another chain drops its signer",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				bsc := f.statement
				bsc.Chain = "eip155:56"
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, bsc)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonBelowK, ReasonWrongBlock},
		},
		{
			"a header that does not hash to the statement's hash, beside the real one",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				other := otherHeader(t, f.raw)
				f.docs.Headers = []Header{{Hash: f.statement.Hash, Raw: other}, {Hash: f.statement.Hash, Raw: f.raw}}
				s := f.statement
				s.HeaderHash = sha256.Sum256(other)
				return nil, []Attestation{f.attest(t, 0, s), f.attest(t, 1, s)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonHeader, ReasonHeader},
		},
		{
			"evidence that does not verify drops the group",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				receipts, transactions := testBlock(3)
				otherProof, err := evm.BuildProof(receipts, transactions, []uint64{2})
				if err != nil {
					t.Fatal(err)
				}
				f.docs.Evidence[0].Proof = otherProof
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonEvidence, ReasonEvidence},
		},
		{
			"a group below k is not proof-checked",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				f.docs.Evidence = nil
				return nil, []Attestation{f.attest(t, 0, f.statement)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonBelowK},
		},
		{
			"a signer with another root is left out",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				other := f.statement
				other.Claims = []statement.Claim{{Asset: usd1, Count: 1, Root: sha256.Sum256(nil)}}
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement), f.attest(t, 2, other)}
			},
			"",
			[]int{0, 1},
			[]string{"", "", ReasonBelowK},
		},
		{
			"two headers share the hash and one is right",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				f.docs.Headers = append([]Header{{Hash: f.statement.Hash, Raw: otherHeader(t, f.raw)}}, f.docs.Headers...)
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			"",
			[]int{0, 1},
			[]string{"", ""},
		},
		{
			"a parent other than the previous verified block",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				return &Block{Number: height - 1, Hash: common.HexToHash("0x02").Hex()},
					[]Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			ReasonParent, nil,
			[]string{"", ""},
		},
		{
			"one key signing twice counts once",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				first := f.attest(t, 0, f.statement)
				second := first
				second.Signature = negateS(t, first.Signature)
				if second.Signature == first.Signature {
					t.Fatal("the second encoding equals the first")
				}
				return nil, []Attestation{first, second}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonBelowK, ReasonBelowK},
		},
		{
			"a capture that does not verify drops only its signer",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				wrong := f.statement
				wrong.Captures = []statement.Capture{{Asset: usd1, Value: "1", ProofHash: f.statement.Captures[0].ProofHash}}
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 2, wrong), f.attest(t, 1, f.statement)}
			},
			"",
			[]int{0, 1},
			[]string{"", ReasonCapture, ""},
		},
		{
			"a signer without the capture stays in its group",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				without := f.statement
				without.Captures = nil
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, without)}
			},
			"",
			[]int{0, 1},
			[]string{"", ""},
		},
		{
			"a listed asset without a claim",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				without := f.statement
				without.Claims = nil
				return nil, []Attestation{f.attest(t, 0, without), f.attest(t, 1, without)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonMissingClaim, ReasonMissingClaim},
		},
		{
			"a claim with no records and a root",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				empty := f.statement
				empty.Claims = []statement.Claim{{Asset: usd1, Count: 0, Root: f.statement.Claims[0].Root}}
				return nil, []Attestation{f.attest(t, 0, empty), f.attest(t, 1, empty)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonEmptyClaim, ReasonEmptyClaim},
		},
		{
			"two groups with the required signers",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				none := f.statement
				none.Claims = []statement.Claim{{Asset: usd1, Count: 0, Root: merkle.Root(nil)}}
				return nil, []Attestation{
					f.attest(t, 0, f.statement), f.attest(t, 1, f.statement), f.attest(t, 0, none), f.attest(t, 2, none),
				}
			},
			ReasonSplit, nil,
			[]string{"", "", "", ""},
		},
		{
			"k signers with a root the evidence does not have",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				s := f.statement
				s.Claims = []statement.Claim{{Asset: usd1, Count: 1, Root: sha256.Sum256(nil)}}
				return nil, []Attestation{f.attest(t, 0, s), f.attest(t, 1, s)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonEvidence, ReasonEvidence},
		},
		{
			"k signers with a count the evidence does not have",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				s := f.statement
				s.Claims = []statement.Claim{{Asset: usd1, Count: 2, Root: f.statement.Claims[0].Root}}
				return nil, []Attestation{f.attest(t, 0, s), f.attest(t, 1, s)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonEvidence, ReasonEvidence},
		},
		{
			"evidence held only for another block",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				f.docs.Evidence[0].BlockHash = common.HexToHash("0x02").Hex()
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonEvidence, ReasonEvidence},
		},
		{
			"capture failures push the group below k",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				wrong := f.statement
				wrong.Captures = []statement.Capture{{Asset: usd1, Value: "1", ProofHash: f.statement.Captures[0].ProofHash}}
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, wrong), f.attest(t, 2, wrong)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonBelowK, ReasonCapture, ReasonCapture},
		},
		{
			"a capture proof that proves another value",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				f.docs.Captures = append(f.docs.Captures, Capture{BlockHash: f.statement.Hash, Asset: usd1, Value: "1", Proof: f.docs.Captures[0].Proof})
				wrong := f.statement
				wrong.Captures = []statement.Capture{{Asset: usd1, Value: "1", ProofHash: f.statement.Captures[0].ProofHash}}
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, wrong), f.attest(t, 2, f.statement)}
			},
			"",
			[]int{0, 2},
			[]string{"", ReasonCapture, ""},
		},
		{
			"a capture whose proof hash is not the held proof's",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				wrong := f.statement
				wrong.Captures = []statement.Capture{{Asset: usd1, Value: f.statement.Captures[0].Value, ProofHash: sha256.Sum256([]byte("x"))}}
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, wrong), f.attest(t, 2, f.statement)}
			},
			"",
			[]int{0, 2},
			[]string{"", ReasonCapture, ""},
		},
		{
			"a statement with another parent hash",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				wrong := f.statement
				wrong.ParentHash = common.HexToHash("0x02").Hex()
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement), f.attest(t, 2, wrong)}
			},
			"",
			[]int{0, 1},
			[]string{"", "", ReasonHeader},
		},
		{
			"a statement with another parent height",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				wrong := f.statement
				wrong.ParentNumber = height - 2
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement), f.attest(t, 2, wrong)}
			},
			"",
			[]int{0, 1},
			[]string{"", "", ReasonHeader},
		},
		{
			"a statement with another timestamp",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				wrong := f.statement
				wrong.Timestamp++
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement), f.attest(t, 2, wrong)}
			},
			"",
			[]int{0, 1},
			[]string{"", "", ReasonHeader},
		},
		{
			"a header with the same time that hashes to another block",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				other := f.header
				other.Extra = []byte{1}
				raw, err := rlp.EncodeToBytes(&other)
				if err != nil {
					t.Fatal(err)
				}
				f.docs.Headers = append(f.docs.Headers, Header{Hash: f.statement.Hash, Raw: raw})
				wrong := f.statement
				wrong.HeaderHash = sha256.Sum256(raw)
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement), f.attest(t, 2, wrong)}
			},
			"",
			[]int{0, 1},
			[]string{"", "", ReasonHeader},
		},
		{
			"BSC milliseconds from mixHash",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				bsc(t, f, 1_700_000_000_900)
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			"",
			[]int{0, 1},
			[]string{"", ""},
		},
		{
			"a BSC timestamp without the mixHash milliseconds",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				bsc(t, f, 1_700_000_000_000)
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonHeader, ReasonHeader},
		},
		{
			"a statement that is not finalized",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				safe := f.statement
				safe.Status = "safe"
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, safe)}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonBelowK, ReasonWrongBlock},
		},
		{
			"another signature type",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				other := f.attest(t, 1, f.statement)
				other.SignatureType = "EdDSA"
				return nil, []Attestation{f.attest(t, 0, f.statement), other}
			},
			ReasonNoAgreement, nil,
			[]string{ReasonBelowK, ReasonSignature},
		},
		{
			"a parent at another height",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				return &Block{Number: height - 2, Hash: f.statement.ParentHash},
					[]Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement)}
			},
			ReasonParent, nil,
			[]string{"", ""},
		},
		{
			"a signer with another count is left out",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				other := f.statement
				other.Claims = []statement.Claim{{Asset: usd1, Count: 2, Root: f.statement.Claims[0].Root}}
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, f.statement), f.attest(t, 2, other)}
			},
			"",
			[]int{0, 1},
			[]string{"", "", ReasonBelowK},
		},
		{
			"a claim for an unlisted asset is ignored",
			func(t *testing.T, f *fixture) (*Block, []Attestation) {
				extra := f.statement
				extra.Claims = []statement.Claim{{Asset: strings.Repeat("22", 20), Count: 5, Root: sha256.Sum256(nil)}, f.statement.Claims[0]}
				return nil, []Attestation{f.attest(t, 0, f.statement), f.attest(t, 1, extra)}
			},
			"",
			[]int{0, 1},
			[]string{"", ""},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			parent, attestations := tc.setup(t, f)
			docs := f.docs
			docs.Attestations = attestations
			c, err := New(f.chain)
			if err != nil {
				t.Fatal(err)
			}
			v := c.Check(height, parent, docs)
			var reasons []string
			for _, r := range v.Results {
				reasons = append(reasons, r.Reason)
			}
			var signers []string
			for _, i := range tc.wantSigners {
				signers = append(signers, f.key(i))
			}
			slices.Sort(signers)
			if v.Accepted != (tc.wantReason == "") || v.Reason != tc.wantReason ||
				!slices.Equal(v.Signers, signers) || !slices.Equal(reasons, tc.wantResults) {
				t.Fatalf("Check = accepted %v, reason %q, signers %v, results %q\nwant reason %q, signers %v, results %q",
					v.Accepted, v.Reason, v.Signers, reasons, tc.wantReason, signers, tc.wantResults)
			}
			if v.Accepted {
				want := Block{Number: height, Hash: f.statement.Hash, ParentNumber: height - 1, ParentHash: f.statement.ParentHash}
				if !reflect.DeepEqual(v.Block, want) {
					t.Fatalf("Block = %+v, want %+v", v.Block, want)
				}
			}
		})
	}
}

// bsc makes the block a BSC block whose mixHash carries 900 milliseconds, and sets the statement's timestamp to ms.
func bsc(t *testing.T, f *fixture, ms uint64) {
	t.Helper()
	f.chain.Chain, f.statement.Chain = "eip155:56", "eip155:56"
	h := f.header
	h.MixDigest = common.BigToHash(big.NewInt(900))
	f.setHeader(t, h, ms)
}

// otherHeader returns raw with its time one second later: a valid header for another block.
func otherHeader(t *testing.T, raw []byte) []byte {
	t.Helper()
	var h types.Header
	if err := rlp.DecodeBytes(raw, &h); err != nil {
		t.Fatal(err)
	}
	h.Time++
	other, err := rlp.EncodeToBytes(&h)
	if err != nil {
		t.Fatal(err)
	}
	return other
}

// negateS returns the other valid encoding of an ECDSA signature: the same R with S replaced by n-S. It writes the DER
// itself, because Signature.Serialize always writes the low S.
func negateS(t *testing.T, signature string) string {
	t.Helper()
	der, err := hex.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ecdsa.ParseDERSignature(der)
	if err != nil {
		t.Fatal(err)
	}
	r, s := parsed.R(), parsed.S()
	rBytes, sBytes := r.Bytes(), s.Negate().Bytes()
	body := append(derInteger(rBytes[:]), derInteger(sBytes[:])...)
	return hex.EncodeToString(append([]byte{0x30, byte(len(body))}, body...))
}

// derInteger encodes a positive big-endian integer as a DER INTEGER.
func derInteger(b []byte) []byte {
	for len(b) > 1 && b[0] == 0 {
		b = b[1:]
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return append([]byte{0x02, byte(len(b))}, b...)
}

// testBlock returns n distinct legacy transactions with a receipt each.
func testBlock(n int) (types.Receipts, types.Transactions) {
	to := common.HexToAddress("0x" + usd1)
	receipts := make(types.Receipts, n)
	transactions := make(types.Transactions, n)
	for i := range n {
		transactions[i] = types.NewTx(&types.LegacyTx{Nonce: uint64(i), To: &to, Gas: 21000, GasPrice: big.NewInt(1)})
		receipts[i] = &types.Receipt{
			Status: types.ReceiptStatusSuccessful, CumulativeGasUsed: 21000 * uint64(i+1),
			Logs: []*types.Log{{Address: to, Data: []byte{byte(i)}}},
		}
	}
	return receipts, transactions
}

// testRecords returns the encoded record of the transaction at index, and the Merkle root of the records.
func testRecords(t *testing.T, receipts types.Receipts, transactions types.Transactions, index uint64) ([]byte, [sha256.Size]byte) {
	t.Helper()
	receipt, err := receipts[index].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	transaction, err := transactions[index].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	records, root, err := evm.EncodeRecords([]evm.Record{{Index: index, Receipt: receipt, Transaction: transaction}})
	if err != nil {
		t.Fatal(err)
	}
	return records, root
}

// Hashes are free-form strings in families whose hashes are not hex, so a separator inside one must not merge groups.
func TestGroupKeyDistinct(t *testing.T) {
	t.Parallel()
	a := statement.Statement{Hash: "a|b", ParentHash: "c"}
	b := statement.Statement{Hash: "a", ParentHash: "b|c"}
	if groupKey(a, nil) == groupKey(b, nil) {
		t.Fatalf("groupKey gives %q for both", groupKey(a, nil))
	}
}
