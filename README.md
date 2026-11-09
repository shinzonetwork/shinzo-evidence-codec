# shinzo-evidence-codec

Go library for the block statements Shinzo generators sign and the evidence hosts check them against.

## Packages

| package | contents |
| --- | --- |
| `statement` | Encoding and decoding of the statement a generator signs for each block |
| `sig` | ES256K signature verification over a statement |
| `merkle` | RFC 9162 Merkle tree hash with SHA-256 |
| `evm` | EVM headers and block time, receipt and transaction records with their proofs, account and storage proofs |
| `rule` | Decides whether enough of a chain's listed signers agree on a block, checking each signed claim against the documents held for it |

`rule` picks a chain's family by its CAIP-2 namespace. It implements the `evm` family (Ethereum, BSC and other `eip155` chains), and `rule.New` refuses any other namespace.

## Test vectors

`testdata/vectors` holds one Ethereum and one BSC block: the node's answers (`*.node.json.gz`) and the codec's outputs for that block (`*.json`). Other implementations can check their outputs against these files.

## Development

```sh
go test ./...
golangci-lint run
```

CI runs golangci-lint v2.15.0.

## License

MIT
