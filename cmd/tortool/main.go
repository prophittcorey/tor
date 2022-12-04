package main

import (
	"flag"
	"fmt"

	"github.com/prophittcorey/tor"
)

func main() {
	var ip string
	var list bool

	flag.StringVar(&ip, "ip", "", "an ip address to analyze")
	flag.BoolVar(&list, "list", false, "if set, the tool will dump a list of all known IP addresses")

	flag.Parse()

	if list {
		fmt.Printf("123.123.123.123\n111.111.111.111\n")

		return
	}

	if len(ip) == 0 {
		flag.Usage()
		return
	}

	val, err := tor.IsExitNode(ip)

	if err != nil {
		fmt.Printf("error checking address; %s\n", err)
	}

	fmt.Printf("%s: %v\n", ip, val)
}
