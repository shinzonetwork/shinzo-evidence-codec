// Package statement encodes the statement a generator signs for each block.
package statement

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

const (
	// Domain is the first field of every statement.
	Domain = "SHINZO/BLOCK/v1"
	// FilterContractLog selects the transactions that emitted a log from a tracked contract.
	FilterContractLog = "evm/contract-log/v1"
	// StatusFinalized is the only status a generator signs.
	StatusFinalized = "finalized"
)

// Errors returned by Encode and Decode.
var (
	ErrDomain       = errors.New("unknown statement domain")
	ErrUnsorted     = errors.New("assets out of order or repeated")
	ErrTruncated    = errors.New("statement ends early")
	ErrTrailing     = errors.New("bytes after the statement")
	ErrFieldTooLong = errors.New("string longer than 65535 bytes")
)

// Statement is what a generator attests about one block. Strings are encoded with a uint16 length,
// integers as uint64 and lists with a uint64 count, all big-endian.
type Statement struct {
	Chain      string // CAIP-2 chain ID
	Number     uint64
	Hash       string
	ParentHash string
	Timestamp  uint64 // milliseconds
	Status     string
	Extractor  string
	Filter     string
	HeaderHash [sha256.Size]byte // SHA-256 of the raw header
	Items      uint64            // receipts in the block, on EVM chains
	Claims     []Claim           // one per tracked asset, including assets with no records
	Captures   []Capture
}

// Claim is what the generator found in the block for one asset.
type Claim struct {
	Asset string
	Count uint64            // records, one per matching transaction
	Root  [sha256.Size]byte // merkle.Root of the records
}

// Capture is an asset's state value at the block.
type Capture struct {
	Asset     string
	Value     string            // decimal, in base units
	ProofHash [sha256.Size]byte // SHA-256 of the proof
}

// Encode returns the bytes a generator signs. Claims and captures must each be sorted by asset.
func (s Statement) Encode() ([]byte, error) {
	if err := s.checkOrder(); err != nil {
		return nil, err
	}
	var e encoder
	e.str(Domain)
	e.str(s.Chain)
	e.u64(s.Number)
	e.str(s.Hash)
	e.str(s.ParentHash)
	e.u64(s.Timestamp)
	e.str(s.Status)
	e.str(s.Extractor)
	e.str(s.Filter)
	e.h32(s.HeaderHash)
	e.u64(s.Items)
	e.u64(uint64(len(s.Claims)))
	for _, c := range s.Claims {
		e.str(c.Asset)
		e.u64(c.Count)
		e.h32(c.Root)
	}
	e.u64(uint64(len(s.Captures)))
	for _, c := range s.Captures {
		e.str(c.Asset)
		e.str(c.Value)
		e.h32(c.ProofHash)
	}
	if e.err != nil {
		return nil, e.err
	}
	return e.b, nil
}

// Decode parses bytes written by Encode.
func Decode(b []byte) (Statement, error) {
	d := decoder{b: b}
	if domain := d.str(); d.err == nil && domain != Domain {
		return Statement{}, fmt.Errorf("%w: %q", ErrDomain, domain)
	}
	s := Statement{
		Chain:      d.str(),
		Number:     d.u64(),
		Hash:       d.str(),
		ParentHash: d.str(),
		Timestamp:  d.u64(),
		Status:     d.str(),
		Extractor:  d.str(),
		Filter:     d.str(),
		HeaderHash: d.h32(),
		Items:      d.u64(),
	}
	for n := d.u64(); n > 0 && d.err == nil; n-- {
		s.Claims = append(s.Claims, Claim{Asset: d.str(), Count: d.u64(), Root: d.h32()})
	}
	for n := d.u64(); n > 0 && d.err == nil; n-- {
		s.Captures = append(s.Captures, Capture{Asset: d.str(), Value: d.str(), ProofHash: d.h32()})
	}
	if d.err != nil {
		return Statement{}, d.err
	}
	if len(d.b) > 0 {
		return Statement{}, fmt.Errorf("%w: %d", ErrTrailing, len(d.b))
	}
	if err := s.checkOrder(); err != nil {
		return Statement{}, err
	}
	return s, nil
}

func (s Statement) checkOrder() error {
	for i := 1; i < len(s.Claims); i++ {
		if s.Claims[i].Asset <= s.Claims[i-1].Asset {
			return fmt.Errorf("claim %q: %w", s.Claims[i].Asset, ErrUnsorted)
		}
	}
	for i := 1; i < len(s.Captures); i++ {
		if s.Captures[i].Asset <= s.Captures[i-1].Asset {
			return fmt.Errorf("capture %q: %w", s.Captures[i].Asset, ErrUnsorted)
		}
	}
	return nil
}

type encoder struct {
	b   []byte
	err error
}

func (e *encoder) str(s string) {
	n := len(s)
	if n > math.MaxUint16 {
		e.err = ErrFieldTooLong
		return
	}
	e.b = binary.BigEndian.AppendUint16(e.b, uint16(n))
	e.b = append(e.b, s...)
}

func (e *encoder) u64(v uint64) {
	e.b = binary.BigEndian.AppendUint64(e.b, v)
}

func (e *encoder) h32(h [sha256.Size]byte) {
	e.b = append(e.b, h[:]...)
}

const (
	lengthSize = 2 // the uint16 before a string
	uint64Size = 8
)

// decoder reads fields in order. After the first error every read returns a zero value.
type decoder struct {
	b   []byte
	err error
}

func (d *decoder) next(n int) []byte {
	if d.err != nil {
		return nil
	}
	if len(d.b) < n {
		d.err = ErrTruncated
		return nil
	}
	p := d.b[:n]
	d.b = d.b[n:]
	return p
}

func (d *decoder) str() string {
	p := d.next(lengthSize)
	if p == nil {
		return ""
	}
	return string(d.next(int(binary.BigEndian.Uint16(p))))
}

func (d *decoder) u64() uint64 {
	p := d.next(uint64Size)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint64(p)
}

func (d *decoder) h32() [sha256.Size]byte {
	var h [sha256.Size]byte
	copy(h[:], d.next(sha256.Size))
	return h
}
