package piholeapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
)

func TestReauthenticatesOnceOn401(t *testing.T) {
	var logins, calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth":
			n := logins.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"session": map[string]any{"valid": true, "sid": fmt.Sprintf("sid%d", n)}})
		case "/api/lists":
			calls.Add(1)
			if r.Header.Get("X-FTL-SID") == "sid1" { // first session "expired"
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":{"key":"unauthorized","message":"Unauthorized"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"lists":[{"address":"https://a","type":"block","enabled":true,"groups":[0]}]}`))
		}
	}))
	defer srv.Close()

	c := New(srv.URL, "pw", nil)
	lists, err := c.Lists(context.Background())
	if err != nil {
		t.Fatalf("Lists: %v", err)
	}
	if len(lists) != 1 || lists[0].Address != "https://a" {
		t.Fatalf("unexpected lists: %+v", lists)
	}
	if logins.Load() != 2 || calls.Load() != 2 {
		t.Fatalf("logins=%d calls=%d, want 2 and 2", logins.Load(), calls.Load())
	}
}

func TestGivesUpAfterSecond401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth" {
			_, _ = w.Write([]byte(`{"session":{"valid":true,"sid":"s"}}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "pw", nil).Lists(context.Background()); !IsUnauthorized(err) {
		t.Fatalf("want unauthorized, got %v", err)
	}
}

func TestBadPassword(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"session":{"valid":false,"message":"password incorrect"}}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "bad", nil).Groups(context.Background()); !IsUnauthorized(err) {
		t.Fatalf("want unauthorized, got %v", err)
	}
}

func TestItemErrorsSurfaceOn2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth" {
			_, _ = w.Write([]byte(`{"session":{"valid":true,"sid":"s"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"processed":{"errors":[{"item":"bad..","error":"invalid domain"}],"success":[]}}`))
	}))
	defer srv.Close()
	err := New(srv.URL, "pw", nil).AddDomain(context.Background(), Domain{Domain: "bad..", Type: "deny", Kind: "exact"})
	if err == nil {
		t.Fatal("want item error, got nil")
	}
}

func TestPathEscaping(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/auth" {
			_, _ = w.Write([]byte(`{"session":{"valid":true,"sid":"s"}}`))
			return
		}
		got = r.URL.EscapedPath() + "?" + r.URL.RawQuery
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New(srv.URL, "pw", nil)
	ctx := context.Background()

	if err := c.DeleteList(ctx, "https://example.com/a b.txt", "block"); err != nil {
		t.Fatal(err)
	}
	if want := "/api/lists/https:%2F%2Fexample.com%2Fa%20b.txt?type=block"; got != want {
		t.Errorf("list path = %s, want %s", got, want)
	}
	if err := c.DeleteDomain(ctx, Domain{Domain: `^ads\.`, Type: "deny", Kind: "regex"}); err != nil {
		t.Fatal(err)
	}
	if want := `/api/domains/deny/regex/%5Eads%5C.?`; got != want {
		t.Errorf("domain path = %s, want %s", got, want)
	}
}

// TestContract runs against a real Pi-hole v6 when PIHOLE_TEST_URL and
// PIHOLE_TEST_PASSWORD are set, e.g.
//
//	docker run -d -p 18080:80 -e FTLCONF_webserver_api_password=pw pihole/pihole:2025.11.0
//	PIHOLE_TEST_URL=http://localhost:18080 PIHOLE_TEST_PASSWORD=pw go test ./internal/piholeapi -run Contract
func TestContract(t *testing.T) {
	base, pw := os.Getenv("PIHOLE_TEST_URL"), os.Getenv("PIHOLE_TEST_PASSWORD")
	if base == "" {
		t.Skip("PIHOLE_TEST_URL not set")
	}
	ctx := context.Background()
	c := New(base, pw, nil)
	defer func() { _ = c.Logout(ctx) }()

	l := List{Address: "https://example.invalid/contract.txt", Type: "block", Comment: "c", Groups: []int{0}, Enabled: true}
	_ = c.DeleteList(ctx, l.Address, l.Type)
	if err := c.AddList(ctx, l); err != nil {
		t.Fatalf("AddList: %v", err)
	}
	l.Enabled = false
	if err := c.UpdateList(ctx, l); err != nil {
		t.Fatalf("UpdateList: %v", err)
	}
	lists, err := c.Lists(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range lists {
		if x.Address == l.Address {
			found = !x.Enabled
		}
	}
	if !found {
		t.Fatalf("updated list not found disabled in %+v", lists)
	}
	if err := c.DeleteList(ctx, l.Address, l.Type); err != nil {
		t.Fatalf("DeleteList: %v", err)
	}

	d := Domain{Domain: `^contract\.`, Type: "deny", Kind: "regex", Groups: []int{0}, Enabled: true}
	_ = c.DeleteDomain(ctx, d)
	if err := c.AddDomain(ctx, d); err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	d.Comment = "updated"
	if err := c.UpdateDomain(ctx, d); err != nil {
		t.Fatalf("UpdateDomain: %v", err)
	}
	if err := c.DeleteDomain(ctx, d); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}

	if err := c.SetLocalRecords(ctx, []string{"10.9.9.9 contract.lan"}, []string{"alias.lan,contract.lan"}); err != nil {
		t.Fatalf("SetLocalRecords: %v", err)
	}
	hosts, cnames, err := c.LocalRecords(ctx)
	if err != nil || len(hosts) != 1 || len(cnames) != 1 {
		t.Fatalf("LocalRecords = %v %v %v", hosts, cnames, err)
	}
	if err := c.SetLocalRecords(ctx, nil, nil); err != nil {
		t.Fatal(err)
	}

	_ = c.DeleteGroup(ctx, "contract")
	g, err := c.AddGroup(ctx, "contract", "c")
	if err != nil {
		t.Fatalf("AddGroup: %v", err)
	}
	g.Enabled, g.Comment = false, "c2"
	if err := c.UpdateGroup(ctx, g); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	cl := ClientEntry{Client: "10.9.0.0/24", Comment: "c", Groups: []int{0, g.ID}}
	_ = c.DeleteClient(ctx, cl.Client)
	if err := c.AddClient(ctx, cl); err != nil {
		t.Fatalf("AddClient: %v", err)
	}
	cl.Groups = []int{g.ID}
	if err := c.UpdateClient(ctx, cl); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	clients, err := c.Clients(ctx)
	if err != nil || len(clients) == 0 || clients[len(clients)-1].Client != cl.Client {
		t.Fatalf("Clients = %+v %v", clients, err)
	}
	if err := c.DeleteClient(ctx, cl.Client); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if err := c.DeleteGroup(ctx, "contract"); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
}
