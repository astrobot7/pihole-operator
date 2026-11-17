package piholesync

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/astrobot7/pihole-operator/api/v1alpha1"
	"github.com/astrobot7/pihole-operator/internal/piholeapi"
	"github.com/astrobot7/pihole-operator/internal/piholeapi/fakepihole"
)

func meta(name string) metav1.ObjectMeta { return metav1.ObjectMeta{Namespace: "dns", Name: name} }

func sample() Desired {
	return Build(
		[]v1alpha1.PiholeBlocklist{{
			ObjectMeta: meta("ads"),
			Spec: v1alpha1.PiholeBlocklistSpec{Lists: []v1alpha1.ListSource{
				{URL: "https://lists/a.txt"}, {URL: "https://lists/b.txt", Enabled: new(false), Comment: "b"},
			}},
		}},
		[]v1alpha1.PiholeDomainList{{
			ObjectMeta: meta("rules"),
			Spec: v1alpha1.PiholeDomainListSpec{Groups: []string{"kids"}, Entries: []v1alpha1.DomainEntry{
				{Domain: "Tracker.Example.", Action: v1alpha1.DomainDeny},
				{Domain: `^ads\.`, Kind: v1alpha1.DomainKindRegex, Action: v1alpha1.DomainDeny},
			}},
		}},
		[]v1alpha1.PiholeLocalRecord{{
			ObjectMeta: meta("lan"),
			Spec: v1alpha1.PiholeLocalRecordSpec{
				A:     []v1alpha1.ARecord{{Host: "nas.lan", IP: "10.0.0.5"}},
				CNAME: []v1alpha1.CNAMERecord{{Host: "files.lan", Target: "nas.lan", TTL: 300}},
			},
		}},
		nil,
	)
}

func TestBuildMergesAndNormalises(t *testing.T) {
	d := Build(
		[]v1alpha1.PiholeBlocklist{
			{ObjectMeta: meta("b"), Spec: v1alpha1.PiholeBlocklistSpec{Groups: []string{"kids"}, Lists: []v1alpha1.ListSource{{URL: "https://x", Enabled: new(true)}}}},
			{ObjectMeta: meta("a"), Spec: v1alpha1.PiholeBlocklistSpec{Lists: []v1alpha1.ListSource{{URL: "https://x", Enabled: new(false), Comment: "first"}}}},
		}, nil, nil, nil)
	if len(d.Lists) != 1 {
		t.Fatalf("want 1 merged list, got %+v", d.Lists)
	}
	l := d.Lists[0]
	if !l.Enabled || !slices.Equal(l.Groups, []string{"Default", "kids"}) || !strings.HasPrefix(l.Comment, "first [") {
		t.Fatalf("bad merge: %+v", l)
	}
	if got := sample().Domains; got[1].Domain != "tracker.example" && got[0].Domain != "tracker.example" {
		t.Fatalf("exact domain not normalised: %+v", got)
	}
	a, b := sample(), sample()
	if a.Hash() != b.Hash() {
		t.Fatal("hash not stable across identical builds")
	}
	b.Hosts = append(b.Hosts, "10.0.0.6 other.lan")
	if a.Hash() == b.Hash() {
		t.Fatal("hash ignores records")
	}
}

func TestConvergeFromEmptyThenIdempotent(t *testing.T) {
	ctx := context.Background()
	f := fakepihole.New()
	d := sample()

	res, err := Converge(ctx, f, d, Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := f.Snapshot()
	if !res.ListsChanged || len(s.Lists) != 2 || len(s.Domains) != 2 || len(s.Hosts) != 1 || len(s.CNAMEs) != 1 {
		t.Fatalf("not converged: res=%+v state=%+v", res, s)
	}
	if s.CNAMEs[0] != "files.lan,nas.lan,300" || s.Hosts[0] != "10.0.0.5 nas.lan" {
		t.Fatalf("record format: %v %v", s.Hosts, s.CNAMEs)
	}
	kids := -1
	for _, g := range s.Groups {
		if g.Name == "kids" {
			kids = g.ID
		}
	}
	if kids <= 0 || !slices.Equal(s.Domains[0].Groups, []int{kids}) {
		t.Fatalf("group not created/resolved: groups=%+v domains=%+v", s.Groups, s.Domains)
	}

	res, err = Converge(ctx, f, d, Options{PreviousHosts: d.Hosts, PreviousCNAMEs: d.CNAMEs})
	if after := f.Snapshot().Writes; err != nil || res.Changes != 0 || after != s.Writes {
		t.Fatalf("second run not a no-op: res=%+v err=%v writes %d->%d", res, err, s.Writes, after)
	}
}

func TestPrunePolicy(t *testing.T) {
	ctx := context.Background()
	handmade := piholeapi.List{Address: "https://stevenblack", Type: "block", Comment: "Migrated", Enabled: true, Groups: []int{0}}
	stale := piholeapi.List{Address: "https://old", Type: "block", Comment: "[" + Marker + ": dns/ads]", Enabled: true, Groups: []int{0}}
	handDomain := piholeapi.Domain{Domain: "mine.example", Type: "allow", Kind: "exact", Groups: []int{0}}

	for _, tc := range []struct {
		name     string
		pruneAll bool
		want     []string
	}{
		{"ManagedOnly keeps hand-made", false, []string{"https://stevenblack"}},
		{"All removes everything undeclared", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := fakepihole.New()
			f.Mutate(func(s *fakepihole.State) {
				s.Lists = []piholeapi.List{handmade, stale}
				s.Domains = []piholeapi.Domain{handDomain}
				s.Hosts = []string{"10.0.0.9 printer.lan", "10.0.0.1 gone.lan"}
			})

			res, err := Converge(ctx, f, Desired{}, Options{PruneAll: tc.pruneAll, PreviousHosts: []string{"10.0.0.1 gone.lan"}})
			if err != nil {
				t.Fatal(err)
			}
			s := f.Snapshot()
			got := make([]string, 0, len(s.Lists))
			for _, l := range s.Lists {
				got = append(got, l.Address)
			}
			if !slices.Equal(got, tc.want) || !res.ListsChanged {
				t.Fatalf("lists = %v (changed=%v), want %v", got, res.ListsChanged, tc.want)
			}
			wantHosts := []string{"10.0.0.9 printer.lan"}
			wantDomains := 1
			if tc.pruneAll {
				wantHosts, wantDomains = []string{}, 0
			}
			if !slices.Equal(s.Hosts, wantHosts) || len(s.Domains) != wantDomains {
				t.Fatalf("hosts=%v domains=%v", s.Hosts, s.Domains)
			}
		})
	}
}

func TestUpdatesDriftedEntries(t *testing.T) {
	ctx := context.Background()
	f := fakepihole.New()
	d := sample()
	if _, err := Converge(ctx, f, d, Options{}); err != nil {
		t.Fatal(err)
	}
	f.Mutate(func(s *fakepihole.State) { s.Lists[0].Enabled = !s.Lists[0].Enabled }) // flipped in the UI
	res, err := Converge(ctx, f, d, Options{PreviousHosts: d.Hosts, PreviousCNAMEs: d.CNAMEs})
	if err != nil || res.Changes != 1 || res.ListsChanged {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

func TestPartialFailureContinues(t *testing.T) {
	f := fakepihole.New()
	f.FailOn("tracker")
	res, err := Converge(context.Background(), f, sample(), Options{})
	if err == nil || !strings.Contains(err.Error(), "tracker.example") {
		t.Fatalf("want error naming the failed domain, got %v", err)
	}
	s := f.Snapshot()
	if len(s.Domains) != 1 || len(s.Lists) != 2 || len(s.Hosts) != 1 || res.Changes == 0 {
		t.Fatalf("other items should still apply: %+v", s)
	}
}

// TestConvergeContract runs Converge against a real Pi-hole (see piholeapi.TestContract).
func TestConvergeContract(t *testing.T) {
	base := os.Getenv("PIHOLE_TEST_URL")
	if base == "" {
		t.Skip("PIHOLE_TEST_URL not set")
	}
	ctx := context.Background()
	c := piholeapi.New(base, os.Getenv("PIHOLE_TEST_PASSWORD"), nil)
	defer func() { _ = c.Logout(ctx) }()
	d := sample()
	if _, err := Converge(ctx, c, d, Options{}); err != nil {
		t.Fatalf("first converge: %v", err)
	}
	res, err := Converge(ctx, c, d, Options{PreviousHosts: d.Hosts, PreviousCNAMEs: d.CNAMEs})
	if err != nil || res.Changes != 0 {
		t.Fatalf("second converge should be a no-op: %+v %v", res, err)
	}
	if _, err := Converge(ctx, c, Desired{}, Options{PreviousHosts: d.Hosts, PreviousCNAMEs: d.CNAMEs}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	lists, _ := c.Lists(ctx)
	for _, l := range lists {
		if strings.Contains(l.Comment, Marker) {
			t.Fatalf("managed list left behind: %+v", l)
		}
	}
}

func groupsSample() []v1alpha1.PiholeGroup {
	f := false
	return []v1alpha1.PiholeGroup{
		{ObjectMeta: meta("kids"), Spec: v1alpha1.PiholeGroupSpec{
			Description: "kids devices", ExcludeFromDefault: true,
			Clients: []string{"aa-bb-cc-dd-ee-ff", "10.0.5.0/24", " tablet.lan "},
		}},
		{ObjectMeta: meta("guests"), Spec: v1alpha1.PiholeGroupSpec{
			Enabled: &f, Clients: []string{"10.0.5.0/24", ":wlan1"},
		}},
		{ObjectMeta: meta("defaults"), Spec: v1alpha1.PiholeGroupSpec{
			Name: "Default", Clients: []string{"192.168.1.2"},
		}},
	}
}

func clientGroups(d Desired) map[string][]string {
	m := map[string][]string{}
	for _, c := range d.Clients {
		m[c.Client] = c.Groups
	}
	return m
}

func TestBuildGroupsAndClients(t *testing.T) {
	d := Build(nil, nil, nil, groupsSample())

	if len(d.GroupDefs) != 2 || d.GroupDefs[0].Name != "guests" || d.GroupDefs[0].Enabled || !d.GroupDefs[1].Enabled {
		t.Fatalf("group defs = %+v (Default must not be declared, guests disabled)", d.GroupDefs)
	}
	if !strings.HasPrefix(d.GroupDefs[1].Comment, "kids devices [") {
		t.Fatalf("description not used as comment: %q", d.GroupDefs[1].Comment)
	}
	got := clientGroups(d)
	want := map[string][]string{
		"AA:BB:CC:DD:EE:FF": {"kids"},                      // MAC normalised, excluded from Default
		"tablet.lan":        {"kids"},                      // whitespace trimmed
		"10.0.5.0/24":       {"Default", "guests", "kids"}, // guests keeps Default
		":wlan1":            {"Default", "guests"},
		"192.168.1.2":       {"Default"},
	}
	if len(got) != len(want) {
		t.Fatalf("clients = %v", got)
	}
	for c, g := range want {
		if !slices.Equal(got[c], g) {
			t.Errorf("client %s groups = %v, want %v", c, got[c], g)
		}
	}
}

func TestConvergeGroupsAndClients(t *testing.T) {
	ctx := context.Background()
	f := fakepihole.New()
	f.Mutate(func(s *fakepihole.State) {
		s.Groups = append(s.Groups, piholeapi.Group{Name: "handmade", Comment: "mine", Enabled: true, ID: 5})
	})
	d := Build(nil, nil, nil, groupsSample())
	if _, err := Converge(ctx, f, d, Options{}); err != nil {
		t.Fatal(err)
	}
	s := f.Snapshot()
	ids := map[string]piholeapi.Group{}
	for _, g := range s.Groups {
		ids[g.Name] = g
	}
	if ids["guests"].Enabled || !ids["kids"].Enabled || len(s.Clients) != 5 {
		t.Fatalf("groups=%+v clients=%+v", s.Groups, s.Clients)
	}
	for _, c := range s.Clients {
		if c.Client == "10.0.5.0/24" && !slices.Equal(c.Groups, []int{0, ids["guests"].ID, ids["kids"].ID}) {
			t.Fatalf("group IDs not resolved: %+v", c)
		}
	}

	// Idempotent.
	res, err := Converge(ctx, f, d, Options{})
	if err != nil || res.Changes != 0 {
		t.Fatalf("second run: %+v %v", res, err)
	}

	// Drop the kids group: its managed group and exclusive clients go, hand-made group stays.
	d = Build(nil, nil, nil, groupsSample()[1:])
	if _, err := Converge(ctx, f, d, Options{}); err != nil {
		t.Fatal(err)
	}
	s = f.Snapshot()
	names := make([]string, 0, len(s.Groups))
	for _, g := range s.Groups {
		names = append(names, g.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"Default", "guests", "handmade"}) {
		t.Fatalf("groups after prune = %v", names)
	}
	if len(s.Clients) != 3 {
		t.Fatalf("clients after prune = %+v", s.Clients)
	}
}

// TestConvergeGroupsContract runs group/client convergence against a real Pi-hole.
func TestConvergeGroupsContract(t *testing.T) {
	base := os.Getenv("PIHOLE_TEST_URL")
	if base == "" {
		t.Skip("PIHOLE_TEST_URL not set")
	}
	ctx := context.Background()
	c := piholeapi.New(base, os.Getenv("PIHOLE_TEST_PASSWORD"), nil)
	defer func() { _ = c.Logout(ctx) }()
	d := Build(nil, nil, nil, groupsSample())
	if _, err := Converge(ctx, c, d, Options{}); err != nil {
		t.Fatalf("converge: %v", err)
	}
	if res, err := Converge(ctx, c, d, Options{}); err != nil || res.Changes != 0 {
		t.Fatalf("second converge should be a no-op: %+v %v", res, err)
	}
	if _, err := Converge(ctx, c, Desired{}, Options{}); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	gs, _ := c.Groups(ctx)
	cl, _ := c.Clients(ctx)
	for _, g := range gs {
		if strings.Contains(g.Comment, Marker) {
			t.Fatalf("managed group left behind: %+v", g)
		}
	}
	for _, x := range cl {
		if strings.Contains(x.Comment, Marker) {
			t.Fatalf("managed client left behind: %+v", x)
		}
	}
}
