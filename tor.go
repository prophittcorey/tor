// Package tor implements routines for analyzing IP addresses associated with
// the Tor network.
package tor

// IsExitNode returns true if an address is a known Tor exit node, false
// otherwise.
func IsExitNode(address string) (bool, error) {
	return false, nil
}

// ExitNodes returns a slice of all known exit node addresses.
func ExitNodes() []string {
	return nil
}
