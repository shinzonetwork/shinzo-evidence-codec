package rule

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/shinzonetwork/shinzo-evidence-codec/statement"
)

// family checks what differs between chain families. Its constructor validates the chain ID and assets once.
type family interface {
	// header checks raw against the statement's hash, number, parent and time, and returns the checks bound to that
	// block.
	header(raw []byte, s statement.Statement) (blockChecks, error)
}

// blockChecks checks records and state captures against one block's commitments. A family whose chain does not
// commit to a part still decodes it, so its count, root or value is compared, and skips only the proof.
type blockChecks interface {
	records(asset Asset, records, proof []byte) (count uint64, root [sha256.Size]byte, err error)
	capture(asset Asset, proof []byte) (value string, err error)
}

// newFamily picks the family by the chain ID's CAIP-2 namespace.
func newFamily(c Config) (family, error) {
	if namespace, _, _ := strings.Cut(c.Chain, ":"); namespace == "eip155" {
		return newEVM(c)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnsupportedChain, c.Chain)
}
