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

var (
	exitnodes   = nodemanager{addresses: map[string]struct{}{}}
	lastFetched = time.Now()

	// RefreshInterval is how often we will re-fetch exit nodes.
	RefreshInterval = 45 * time.Minute

	// UserAgent will be used to set the UserAgent header for all HTTP requests.
	UserAgent = "github.com/prophittcorey/tor"
)

type nodemanager struct {
	sync.RWMutex
	addresses map[string]struct{}
}

// IsExitNode returns true if an address is a known Tor exit node, false
// otherwise.
func IsExitNode(address string) (bool, error) {
	exitnodes.RLock()

	if len(exitnodes.addresses) == 0 || time.Now().After(lastFetched.Add(RefreshInterval)) {
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

	if len(exitnodes.addresses) == 0 || time.Now().After(lastFetched.Add(RefreshInterval)) {
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
	/* aggregate addresses concurrently */

	sources := map[string][]byte{
		"https://check.torproject.org/torbulkexitlist":                                                  []byte{},
		"https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst": []byte{},
		// "https://www.dan.me.uk/torlist/?exit": []byte{},
	}

	wg := sync.WaitGroup{}

	for url, _ := range sources {
		wg.Add(1)

		go (func(url string) {
			defer wg.Done()

			req, err := http.NewRequest(http.MethodGet, url, nil)

			if err != nil {
				return
			}

			req.Header.Set("User-Agent", UserAgent)

			client := http.Client{
				Timeout: 3 * time.Second,
			}

			res, err := client.Do(req)

			if err != nil {
				return
			}

			if bs, err := io.ReadAll(res.Body); err == nil {
				sources[url] = bs
			}
		})(url)
	}

	wg.Wait()

	/* merge / dedupe all addresses */

	addresses := map[string]struct{}{}

	for _, bs := range sources {
		for _, ipaddress := range bytes.Fields(bs) {
			addresses[string(ipaddress)] = struct{}{}
		}
	}

	/* update global exit node addresses */

	exitnodes.Lock()

	exitnodes.addresses = addresses
	lastFetched = time.Now()

	exitnodes.Unlock()

	return nil
}
