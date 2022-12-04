# Tor

Analyze and locate IP addresses coming from the Tor network.

## Usage

```golang
import "github.com/prophittcorey/tor"

tor.IsExitNode("46.182.21.250") // => true, nil

tor.ExitNodes() // => ["46.182.21.250", ...]
```

## License

The source code for this repository is licensed under the MIT license, which you can
find in the [LICENSE](LICENSE.md) file.
