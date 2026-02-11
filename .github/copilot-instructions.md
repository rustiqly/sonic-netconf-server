# Copilot Instructions for sonic-netconf-server

## Project Overview

sonic-netconf-server implements a NETCONF (Network Configuration Protocol) server for SONiC switches. It provides a standards-based XML/YANG interface for network configuration and state retrieval, complementing SONiC's CLI and REST API interfaces. The server includes TACACS+ integration for authentication and authorization.

## Architecture

```
sonic-netconf-server/
├── netconf/              # NETCONF protocol implementation
├── lib/                  # Shared libraries
├── models/               # YANG model handling
├── tacplus/              # TACACS+ authentication integration
├── tools/                # Development and utility tools
├── go.mod                # Go module definition
├── go.sum                # Go dependency checksums
├── Makefile              # Build system
├── debian/               # Debian packaging
└── README.md
```

### Key Concepts
- **NETCONF protocol**: RFC 6241/6242 — XML-based network management protocol over SSH
- **YANG models**: Data models defining configuration and operational state schemas
- **TACACS+**: Terminal Access Controller Access-Control System for AAA (Authentication, Authorization, Accounting)
- **SONiC integration**: Translates NETCONF operations to SONiC Redis DB operations

## Language & Style

- **Primary language**: Go
- **Go version**: See `go.mod` for minimum version
- **Module path**: Check `go.mod` for the module import path
- **Naming conventions**:
  - Exported: `PascalCase` (e.g., `HandleRequest`, `NetconfSession`)
  - Unexported: `camelCase`
  - Files: `snake_case.go`
- **Error handling**: Return errors explicitly — follow Go idioms (`if err != nil`)
- **Formatting**: Run `gofmt` / `goimports` before committing

## Build Instructions

```bash
# Install Go (check go.mod for version)
# Install dependencies
go mod download

# Build
make

# Build Debian package
dpkg-buildpackage -rfakeroot -b -us -uc
```

## Testing

```bash
# Run Go unit tests
go test ./...

# Run with race detector
go test -race ./...
```

## PR Guidelines

- **Signed-off-by**: Required on all commits
- **CLA**: Sign Linux Foundation EasyCLA
- **Testing**: Include unit tests for new functionality
- **gofmt**: Code must be formatted with `gofmt`
- **CI**: Azure pipeline checks must pass

## Gotchas

- **SSH transport**: NETCONF runs over SSH — changes must maintain SSH session handling correctly
- **XML parsing**: NETCONF uses XML — be careful with namespace handling and encoding
- **YANG validation**: Configuration changes must be validated against YANG models
- **TACACS+ dependency**: Authentication changes must work with and without TACACS+ configured
- **Concurrent sessions**: Server must handle multiple NETCONF sessions safely
- **SONiC DB interaction**: Use proper Redis DB access patterns (CONFIG_DB, STATE_DB)
