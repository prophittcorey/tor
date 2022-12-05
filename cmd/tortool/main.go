package main

import (
	"flag"
	"fmt"

	"github.com/prophittcorey/tor"
)

func main() {
	var ip string
	var exitnodes bool

	flag.StringVar(&ip, "ip", "", "an ip address to analyze (returns 'true' if it's an exit node, 'false' otherwise")
	flag.BoolVar(&exitnodes, "exitnodes", false, "if specified, a list of all known exit node IP addresses will be printed")

	flag.Parse()

	if len(ip) > 0 {
		if val, err := tor.IsExitNode(ip); err == nil {
			fmt.Println(val)
		}

		return
	}

	if exitnodes {
		for _, address := range tor.ExitNodes() {
			fmt.Println(address)
		}

		return
	}

	flag.Usage()
}
