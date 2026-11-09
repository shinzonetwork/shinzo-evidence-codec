// Package rule decides whether enough listed signers agree on the block at a height, checking every claim they sign
// against the documents held for that height.
package rule

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/shinzonetwork/shinzo-evidence-codec/merkle"
	"github.com/shinzonetwork/shinzo-evidence-codec/sig"
	"github.com/shinzonetwork/shinzo-evidence-codec/statement"
)

// Errors returned by New.
var (
	ErrRequired         = errors.New("required is not between 1 and the number of signers")
	ErrKey              = errors.New("signer is not a lower-case compressed secp256k1 public key")
	ErrDuplicateKey     = errors.New("signer listed twice")
	ErrAsset            = errors.New("asset id is empty or listed twice")
	ErrUnsupportedChain = errors.New("no family checks the chain's CAIP-2 namespace")
	ErrSettings         = errors.New("chain ID or asset is not valid for the family")
)

// Why an attestation did not count.
const (
	ReasonUnlisted     = "signer is not listed"
	ReasonSignature    = "signature does not verify"
	ReasonStatement    = "statement does not decode"
	ReasonWrongBlock   = "statement names another chain, height or status"
	ReasonHeader       = "no held header matches the statement"
	ReasonMissingClaim = "a listed asset has no claim"
	ReasonEmptyClaim   = "a claim with no records has a non-empty root"
	ReasonBelowK       = "its group has fewer signers than required"
	ReasonEvidence     = "no held evidence matches a claim"
	ReasonCapture      = "no held state capture matches a state entry"
)

// Why a height holds.
const (
	ReasonNoAgreement = "no group has the required signers"
	ReasonSplit       = "more than one group has the required signers"
	ReasonParent      = "the agreed parent is not the previous verified block"
)

// Block is a block's height and hash, with its parent's.
type Block struct {
	Number       uint64
	Hash         string
	ParentNumber uint64
	ParentHash   string
}

// Attestation is a BlockAttestation document.
type Attestation struct {
	Signer        string
	SignatureType string
	Signature     string
	Statement     []byte
}

// Header is a Header document.
type Header struct {
	Hash string
	Raw  []byte
}

// Evidence is an Evidence document.
type Evidence struct {
	BlockHash string
	Asset     string
	Records   []byte
	Proof     []byte
}

// Capture is a StateCapture document.
type Capture struct {
	BlockHash string
	Asset     string
	Value     string
	Proof     []byte
}

// Documents are the documents held at one height.
type Documents struct {
	Attestations []Attestation
	Headers      []Header
	Evidence     []Evidence
	Captures     []Capture
}

// Result is what became of one attestation. An empty Reason means it passed every check; whether its group was
// accepted is in the Verdict.
type Result struct {
	Signer string
	Hash   string // the statement's block hash, when the statement decoded
	Reason string
}

// Verdict is the outcome at one height.
type Verdict struct {
	Accepted bool
	Block    Block
	Signers  []string // the accepted group's keys, sorted
	Reason   string   // why the height holds; empty when accepted
	Results  []Result // one per attestation, in the order given
}

// Config is one chain's rule: the generator keys that may sign, how many of them must agree, and the tracked assets.
type Config struct {
	Chain    string   // CAIP-2 chain ID; its namespace picks the family
	Signers  []string // compressed secp256k1 public keys in lower-case hex
	Required int
	Assets   []Asset
}

// Asset is a tracked asset, its ID in the family's canonical form.
type Asset struct {
	ID         string
	SupplySlot string // evm: the total supply's storage slot, 0x-prefixed hex
}

// Chain applies the rule to one chain.
type Chain struct {
	config Config
	assets map[string]Asset // by ID
	family family
}

// New returns the rule for c. It refuses c unless the signers are distinct valid keys, Required is between 1 and
// their number, the asset IDs are distinct, and the family accepts the chain ID and the assets.
func New(c Config) (*Chain, error) {
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("chain %q: %w", c.Chain, err)
	}
	f, err := newFamily(c)
	if err != nil {
		return nil, fmt.Errorf("chain %q: %w", c.Chain, err)
	}
	assets := make(map[string]Asset, len(c.Assets))
	for _, a := range c.Assets {
		assets[a.ID] = a
	}
	return &Chain{config: c, assets: assets, family: f}, nil
}

func (c Config) validate() error {
	if c.Required < 1 || c.Required > len(c.Signers) {
		return ErrRequired
	}
	keys := make(map[string]bool, len(c.Signers))
	for _, k := range c.Signers {
		if err := checkKey(k); err != nil {
			return err
		}
		if keys[k] {
			return fmt.Errorf("%w: %s", ErrDuplicateKey, k)
		}
		keys[k] = true
	}
	ids := make(map[string]bool, len(c.Assets))
	for _, a := range c.Assets {
		if a.ID == "" || ids[a.ID] {
			return fmt.Errorf("%w: %q", ErrAsset, a.ID)
		}
		ids[a.ID] = true
	}
	return nil
}

func checkKey(key string) error {
	b, err := hex.DecodeString(key)
	if err != nil || len(b) != secp256k1.PubKeyBytesLenCompressed || hex.EncodeToString(b) != key {
		return fmt.Errorf("%w: %q", ErrKey, key)
	}
	if _, err := secp256k1.ParsePubKey(b); err != nil {
		return fmt.Errorf("%w: %w", ErrKey, err)
	}
	return nil
}

// member is an attestation that passed the checks made before grouping.
type member struct {
	result    int // index into Verdict.Results
	statement statement.Statement
	checks    blockChecks
}

// group is the members that agree on the block and on the claims for listed assets.
type group struct {
	members []member
	signers map[string]bool
}

// held is the documents at one height, with the SHA-256 of each header and capture proof computed once, so the cost of
// a check does not multiply with the number of attestations.
type held struct {
	Documents

	headerHashes  [][sha256.Size]byte
	captureHashes [][sha256.Size]byte
}

func newHeld(docs Documents) held {
	h := held{Documents: docs}
	for _, header := range docs.Headers {
		h.headerHashes = append(h.headerHashes, sha256.Sum256(header.Raw))
	}
	for _, capture := range docs.Captures {
		h.captureHashes = append(h.captureHashes, sha256.Sum256(capture.Proof))
	}
	return h
}

// Check decides the block at height number. parent is the last verified block below it, or nil at the first height,
// where the caller checks its own anchor instead.
func (c *Chain) Check(number uint64, parent *Block, docs Documents) Verdict {
	h := newHeld(docs)
	var v Verdict
	groups := c.groupAttestations(&v, number, h)
	agreed := c.agreedGroups(&v, groups, h)
	return decide(v, agreed, parent)
}

// groupAttestations records a Result for each attestation and groups those that pass the checks made before grouping.
func (c *Chain) groupAttestations(v *Verdict, number uint64, h held) []*group {
	var keys []string
	var groups []*group
	for _, a := range h.Attestations {
		s, checks, reason := c.precheck(number, a, h)
		v.Results = append(v.Results, Result{Signer: a.Signer, Hash: s.Hash, Reason: reason})
		if reason != "" {
			continue
		}
		key := groupKey(s, c.assets)
		i := slices.Index(keys, key)
		if i < 0 {
			keys = append(keys, key)
			groups = append(groups, &group{signers: make(map[string]bool)})
			i = len(groups) - 1
		}
		groups[i].members = append(groups[i].members, member{result: len(v.Results) - 1, statement: s, checks: checks})
		groups[i].signers[a.Signer] = true
	}
	return groups
}

// agreedGroups checks proofs in the groups with the required signers and returns those that still have them. Groups
// below the required count are not proof-checked.
func (c *Chain) agreedGroups(v *Verdict, groups []*group, h held) []*group {
	var agreed []*group
	for _, g := range groups {
		if len(g.signers) < c.config.Required {
			g.drop(v, ReasonBelowK)
			continue
		}
		if !c.evidenceHolds(g.members[0], h.Evidence) {
			g.drop(v, ReasonEvidence)
			continue
		}
		g.dropFailedCaptures(v, c, h)
		if len(g.signers) < c.config.Required {
			g.drop(v, ReasonBelowK)
			continue
		}
		agreed = append(agreed, g)
	}
	return agreed
}

// decide accepts the height when exactly one group agrees and its parent is the previous verified block.
func decide(v Verdict, agreed []*group, parent *Block) Verdict {
	switch {
	case len(agreed) == 0:
		v.Reason = ReasonNoAgreement
		return v
	case len(agreed) > 1:
		v.Reason = ReasonSplit
		return v
	}
	s := agreed[0].members[0].statement
	v.Block = Block{Number: s.Number, Hash: s.Hash, ParentNumber: s.ParentNumber, ParentHash: s.ParentHash}
	if parent != nil && (s.ParentNumber != parent.Number || s.ParentHash != parent.Hash) {
		v.Reason = ReasonParent
		return v
	}
	for k := range agreed[0].signers {
		v.Signers = append(v.Signers, k)
	}
	slices.Sort(v.Signers)
	v.Accepted = true
	return v
}

// precheck makes the checks that need no proof. It returns an empty reason when a passes them all.
func (c *Chain) precheck(number uint64, a Attestation, h held) (statement.Statement, blockChecks, string) {
	if !slices.Contains(c.config.Signers, a.Signer) {
		return statement.Statement{}, nil, ReasonUnlisted
	}
	if err := sig.VerifyStatement(a.Statement, a.Signer, a.SignatureType, a.Signature); err != nil {
		return statement.Statement{}, nil, ReasonSignature
	}
	s, err := statement.Decode(a.Statement)
	if err != nil {
		return statement.Statement{}, nil, ReasonStatement
	}
	if s.Chain != c.config.Chain || s.Number != number || s.Status != statement.StatusFinalized {
		return s, nil, ReasonWrongBlock
	}
	checks := c.headerChecks(s, h)
	if checks == nil {
		return s, nil, ReasonHeader
	}
	claimed := make(map[string]bool, len(s.Claims))
	for _, cl := range s.Claims {
		claimed[cl.Asset] = true
		if _, ok := c.assets[cl.Asset]; ok && cl.Count == 0 && cl.Root != merkle.Root(nil) {
			return s, nil, ReasonEmptyClaim
		}
	}
	for id := range c.assets {
		if !claimed[id] {
			return s, nil, ReasonMissingClaim
		}
	}
	return s, checks, ""
}

// headerChecks returns the family's checks for the first held header that matches s, or nil when none does. Several
// Header documents can share a hash, and only one need be right.
func (c *Chain) headerChecks(s statement.Statement, h held) blockChecks {
	for i, header := range h.Headers {
		if header.Hash != s.Hash || h.headerHashes[i] != s.HeaderHash {
			continue
		}
		if checks, err := c.family.header(header.Raw, s); err == nil {
			return checks
		}
	}
	return nil
}

// evidenceHolds reports whether every claim with records has a held Evidence document whose records match the claim
// and whose proof verifies. The result depends only on the block and the claims, which a group's members share.
func (c *Chain) evidenceHolds(m member, evidence []Evidence) bool {
	for _, cl := range m.statement.Claims {
		asset, ok := c.assets[cl.Asset]
		if !ok || cl.Count == 0 {
			continue
		}
		found := slices.ContainsFunc(evidence, func(e Evidence) bool {
			if e.BlockHash != m.statement.Hash || e.Asset != cl.Asset {
				return false
			}
			count, root, err := m.checks.records(asset, e.Records, e.Proof)
			return err == nil && count == cl.Count && root == cl.Root
		})
		if !found {
			return false
		}
	}
	return true
}

// captureHolds reports whether every state entry of a listed asset has a held StateCapture document with its value
// and proof hash whose proof verifies to that value. proven holds each document's verified value, or "" when it does
// not verify, so members of one group share the work.
func (c *Chain) captureHolds(m member, h held, proven map[int]string) bool {
	for _, entry := range m.statement.Captures {
		asset, ok := c.assets[entry.Asset]
		if !ok {
			continue
		}
		found := false
		for i, sc := range h.Captures {
			if sc.BlockHash != m.statement.Hash || sc.Asset != entry.Asset || sc.Value != entry.Value ||
				h.captureHashes[i] != entry.ProofHash {
				continue
			}
			value, done := proven[i]
			if !done {
				value, _ = m.checks.capture(asset, sc.Proof)
				proven[i] = value
			}
			if value == entry.Value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// groupKey identifies what a group's members agree on: the block and the claims for listed assets. Strings are quoted,
// so two different statements cannot share a key.
func groupKey(s statement.Statement, assets map[string]Asset) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%q %q %d %x", s.Hash, s.ParentHash, s.ParentNumber, s.HeaderHash)
	for _, cl := range s.Claims {
		if _, ok := assets[cl.Asset]; ok {
			fmt.Fprintf(&b, " %q %d %x", cl.Asset, cl.Count, cl.Root)
		}
	}
	return b.String()
}

func (g *group) drop(v *Verdict, reason string) {
	for _, m := range g.members {
		v.Results[m.result].Reason = reason
	}
}

// dropFailedCaptures removes the members whose state entries do not verify. A signer counts while any of its
// attestations remains.
func (g *group) dropFailedCaptures(v *Verdict, c *Chain, h held) {
	proven := make(map[int]string)
	kept := g.members[:0]
	for _, m := range g.members {
		if c.captureHolds(m, h, proven) {
			kept = append(kept, m)
		} else {
			v.Results[m.result].Reason = ReasonCapture
		}
	}
	g.members = kept
	g.signers = make(map[string]bool, len(kept))
	for _, m := range kept {
		g.signers[v.Results[m.result].Signer] = true
	}
}
