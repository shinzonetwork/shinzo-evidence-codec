package statement

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func testStatement() Statement {
	return Statement{
		Chain:      "eip155:56",
		Number:     7,
		Hash:       "0xaa",
		ParentHash: "0xbb",
		Timestamp:  8,
		Status:     StatusFinalized,
		Extractor:  "x1",
		Filter:     FilterContractLog,
		HeaderHash: filled(1),
		Items:      9,
		Claims:     []Claim{{Asset: "a1", Count: 2, Root: filled(2)}, {Asset: "b2", Count: 0, Root: filled(3)}},
		Captures:   []Capture{{Asset: "c3", Value: "1000", ProofHash: filled(4)}, {Asset: "d4", Value: "0", ProofHash: filled(5)}},
	}
}

// The expected bytes are written by hand, so a layout mistake shared by Encode and Decode still fails.
func TestEncode(t *testing.T) {
	t.Parallel()
	str := func(s string) string { return hex.EncodeToString([]byte(s)) }
	h32 := func(b byte) string { return strings.Repeat(hex.EncodeToString([]byte{b}), sha256.Size) }
	want, err := hex.DecodeString(strings.Join([]string{
		"000f", str("SHINZO/BLOCK/v1"),
		"0009", str("eip155:56"),
		"0000000000000007",
		"0004", str("0xaa"),
		"0004", str("0xbb"),
		"0000000000000008",
		"0009", str("finalized"),
		"0002", str("x1"),
		"0013", str("evm/contract-log/v1"),
		h32(1),
		"0000000000000009",
		"0000000000000002",
		"0002", str("a1"), "0000000000000002", h32(2),
		"0002", str("b2"), "0000000000000000", h32(3),
		"0000000000000002",
		"0002", str("c3"), "0004", str("1000"), h32(4),
		"0002", str("d4"), "0001", str("0"), h32(5),
	}, ""))
	if err != nil {
		t.Fatal(err)
	}
	s := testStatement()
	got, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Encode =\n%x\nwant\n%x", got, want)
	}
	decoded, err := Decode(want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, s) {
		t.Fatalf("Decode =\n%+v\nwant\n%+v", decoded, s)
	}
}

func TestEncodeRejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		alter   func(s *Statement)
		wantErr error
	}{
		{"claims out of order", func(s *Statement) { s.Claims[0], s.Claims[1] = s.Claims[1], s.Claims[0] }, ErrUnsorted},
		{"repeated claim", func(s *Statement) { s.Claims[1].Asset = s.Claims[0].Asset }, ErrUnsorted},
		{"captures out of order", func(s *Statement) { s.Captures[0], s.Captures[1] = s.Captures[1], s.Captures[0] }, ErrUnsorted},
		{"string too long", func(s *Statement) { s.Extractor = strings.Repeat("x", 1<<16) }, ErrFieldTooLong},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := testStatement()
			tc.alter(&s)
			if _, err := s.Encode(); !errors.Is(err, tc.wantErr) {
				t.Fatalf("Encode = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestDecodeRejects(t *testing.T) {
	t.Parallel()
	encoded, err := testStatement().Encode()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{"another domain", replaceOnce(t, encoded, "SHINZO/BLOCK/v1", "SHINZO/BLOCK/v2"), ErrDomain},
		{"claims out of order", replaceOnce(t, encoded, "b2", "a0"), ErrUnsorted},
		{"repeated claim", replaceOnce(t, encoded, "b2", "a1"), ErrUnsorted},
		{"captures out of order", replaceOnce(t, encoded, "d4", "c2"), ErrUnsorted},
		{"trailing byte", append(bytes.Clone(encoded), 0), ErrTrailing},
	}
	for _, tc := range cases {
		if _, err := Decode(tc.input); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: Decode = %v, want %v", tc.name, err, tc.wantErr)
		}
	}
	for i := range encoded {
		if _, err := Decode(encoded[:i]); !errors.Is(err, ErrTruncated) {
			t.Errorf("first %d bytes: Decode = %v, want %v", i, err, ErrTruncated)
		}
	}
}

func filled(b byte) [sha256.Size]byte {
	var h [sha256.Size]byte
	for i := range h {
		h[i] = b
	}
	return h
}

// replaceOnce returns a copy of b with from replaced by to, failing unless from occurs exactly once.
func replaceOnce(t *testing.T, b []byte, from, to string) []byte {
	t.Helper()
	if n := bytes.Count(b, []byte(from)); n != 1 {
		t.Fatalf("%q occurs %d times", from, n)
	}
	return bytes.Replace(b, []byte(from), []byte(to), 1)
}
