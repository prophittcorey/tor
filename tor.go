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
	// A map of tor exit node sources. All sources will be fetched concurrently
	// and merged together.
	Sources = map[string][]byte{
		"https://check.torproject.org/torbulkexitlist":                                                  []byte{},
		"https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst": []byte{},
	}

	// HTTPClient is used to perform all HTTP requests. You can specify your own
	// to set a custom timeout, proxy, etc.
	HTTPClient = http.Client{
		Timeout: 3 * time.Second,
	}

	// CachePeriod specifies the amount of time an internal cache of exit node addresses are used
	// before refreshing the addresses.
	CachePeriod = 45 * time.Minute

	// UserAgent will be used in each request's user agent header field.
	UserAgent = "github.com/prophittcorey/tor"
)

var (
	exitnodes   = nodemanager{addresses: map[string]struct{}{}}
	lastFetched = time.Now()
)

type nodemanager struct {
	sync.RWMutex
	addresses map[string]struct{}
}

func refreshExitNodeAddresses() error {
	/* aggregate addresses concurrently */

	wg := sync.WaitGroup{}

	for url, _ := range Sources {
		wg.Add(1)

		go (func(url string) {
			defer wg.Done()

			req, err := http.NewRequest(http.MethodGet, url, nil)

			if err != nil {
				return
			}

			req.Header.Set("User-Agent", UserAgent)

			res, err := HTTPClient.Do(req)

			if err != nil {
				return
			}

			if bs, err := io.ReadAll(res.Body); err == nil {
				Sources[url] = bs
			}
		})(url)
	}

	wg.Wait()

	/* merge / dedupe all addresses */

	addresses := map[string]struct{}{}

	for _, bs := range Sources {
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

// IsExitNode returns true if an address is a known Tor exit node, false
// otherwise.
func IsExitNode(address string) (bool, error) {
	exitnodes.RLock()

	if len(exitnodes.addresses) == 0 || time.Now().After(lastFetched.Add(CachePeriod)) {
		exitnodes.RUnlock()

		if err := refreshExitNodeAddresses(); err != nil {
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

	if len(exitnodes.addresses) == 0 || time.Now().After(lastFetched.Add(CachePeriod)) {
		exitnodes.RUnlock()

		if err := refreshExitNodeAddresses(); err != nil {
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
