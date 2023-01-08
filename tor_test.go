package tor

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExitNodes(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "111.111.111.111\n222.222.222.222\n")
	}))

	defer svr.Close()

	svr2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "333.333.333.333\n444.444.444.444\n")
	}))

	defer svr2.Close()

	Sources = map[string][]byte{
		svr.URL:  []byte{},
		svr2.URL: []byte{},
	}

	ips := ExitNodes()

	if len(ips) != 4 {
		t.Fatalf("failed to find four ips; got %d", len(ips))
	}
}

func TestIsExitNode(t *testing.T) {
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "111.111.111.111\n222.222.222.222\n")
	}))

	defer svr.Close()

	svr2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "333.333.333.333\n444.444.444.444\n")
	}))

	defer svr2.Close()

	Sources = map[string][]byte{
		svr.URL:  []byte{},
		svr2.URL: []byte{},
	}

	if exit, err := IsExitNode("111.111.111.111"); err != nil || !exit {
		t.Fatalf("failed to identify an exit node; got 111.111.111.111")
	}

	if exit, err := IsExitNode("222.222.222.222"); err != nil || !exit {
		t.Fatalf("failed to identify an exit node; got 222.222.222.222")
	}
}
