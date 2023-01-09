# Tor

[![Go Reference](https://pkg.go.dev/badge/github.com/prophittcorey/tor.svg)](https://pkg.go.dev/github.com/prophittcorey/tor)

Analyze and identify IP addresses coming from the Tor network.

## Package Usage

```golang
import "github.com/prophittcorey/tor"

tor.IsExitNode("46.182.21.250") // => true, err

tor.ExitNodes() // => ["46.182.21.250", ...]
```

## Tool Usage

```bash
# Install the latest tool.
go install github.com/prophittcorey/tor/cmd/tortool@latest

# Dump all exit nodes.
tortool --exitnodes

# Check a specific IP address.
tortool --ip 46.182.21.250
```

## License

The source code for this repository is licensed under the MIT license, which you can
find in the [LICENSE](LICENSE.md) file.
