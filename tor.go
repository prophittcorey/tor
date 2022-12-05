// Package tor implements routines for analyzing IP addresses associated with
// the Tor network.
package tor

import (
	"bytes"
	"io"
	"net/http"
	"sync"
	"time"
)

type nodemanager struct {
	sync.RWMutex
	addresses map[string]struct{}
}

var (
	exitnodes = nodemanager{addresses: map[string]struct{}{}}
)

// IsExitNode returns true if an address is a known Tor exit node, false
// otherwise.
func IsExitNode(address string) (bool, error) {
	exitnodes.RLock()

	if len(exitnodes.addresses) == 0 {
		exitnodes.RUnlock()

		if err := refreshAddresses(); err != nil {
			return false, err
		}

		exitnodes.RLock()
	}

	defer exitnodes.RUnlock()

	if _, ok := exitnodes.addresses[address]; ok {
		return true, nil
	}

	return false, nil
}

// ExitNodes returns a slice of all known exit node addresses.
func ExitNodes() []string {
	exitnodes.RLock()

	if len(exitnodes.addresses) == 0 {
		exitnodes.RUnlock()

		if err := refreshAddresses(); err != nil {
			return []string{}
		}

		exitnodes.RLock()
	}

	defer exitnodes.RUnlock()

	nodes := []string{}

	for addr := range exitnodes.addresses {
		nodes = append(nodes, addr)
	}

	return nodes
}

func refreshAddresses() error {
	/* aggregate addresses */

	sources := []string{
		"https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
	}

	addresses := map[string]struct{}{}

	for _, url := range sources {
		req, err := http.NewRequest(http.MethodGet, url, nil)

		if err != nil {
			continue
		}

		client := http.Client{
			Timeout: 3 * time.Second,
		}

		res, err := client.Do(req)

		if err != nil {
			continue
		}

		if bs, err := io.ReadAll(res.Body); err == nil {
			for _, addrbs := range bytes.Fields(bs) {
				addresses[string(addrbs)] = struct{}{}
			}
		}
	}

	/* update global exit node addresses */

	exitnodes.Lock()

	defer exitnodes.Unlock()

	exitnodes.addresses = addresses

	return nil
}
