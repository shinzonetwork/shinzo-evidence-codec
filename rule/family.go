package rule

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/shinzonetwork/shinzo-evidence-codec/statement"
	"github.com/shinzonetwork/shinzo-evidence-codec/trust"
)

// Errors returned by New.
var (
	ErrUnknownFamily = errors.New("unknown chain family")
	ErrSettings      = errors.New("chain or asset settings are not valid for the family")
)

// family checks what differs between chain families. Its constructor validates the chain's settings once.
type family interface {
	// header checks raw against the statement's hash, number, parent and time, and returns the checks bound to that
	// block.
	header(raw []byte, s statement.Statement) (blockChecks, error)
}

// blockChecks checks records and state captures against one block's commitments. A family whose chain does not
// commit to a part still decodes it, so its count, root or value is compared, and skips only the proof.
type blockChecks interface {
	records(asset trust.Asset, records, proof []byte) (count uint64, root [sha256.Size]byte, err error)
	capture(asset trust.Asset, proof []byte) (value string, err error)
}

const familyEVM = "evm"

func newFamily(c trust.Chain) (family, error) {
	if c.Family == familyEVM {
		return newEVM(c)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownFamily, c.Family)
}
