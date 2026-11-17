// Package fakepihole is an in-memory Pi-hole for tests.
package fakepihole

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/astrobot7/pihole-operator/internal/piholeapi"
)

// State is the content of a fake Pi-hole.
type State struct {
	Lists       []piholeapi.List
	Domains     []piholeapi.Domain
	Groups      []piholeapi.Group
	Clients     []piholeapi.ClientEntry
	Hosts       []string
	CNAMEs      []string
	Writes      int
	GravityRuns int
}

// Pihole implements the API surface the operator uses, in memory. Safe for concurrent use.
type Pihole struct {
	mu sync.Mutex
	s  State
	// failOn makes writes for any list/domain containing this substring fail.
	failOn string
}

// New returns a Pi-hole with only the Default group.
func New() *Pihole {
	return &Pihole{s: State{Groups: []piholeapi.Group{{Name: "Default", ID: 0, Enabled: true}}}}
}

// Snapshot returns a copy of the current state.
func (f *Pihole) Snapshot() State {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.s
	s.Lists, s.Domains, s.Groups = slices.Clone(s.Lists), slices.Clone(s.Domains), slices.Clone(s.Groups)
	s.Clients = slices.Clone(s.Clients)
	s.Hosts, s.CNAMEs = slices.Clone(s.Hosts), slices.Clone(s.CNAMEs)
	return s
}

// Mutate edits state directly, e.g. to simulate a change made in the web UI.
func (f *Pihole) Mutate(fn func(*State)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.s)
}

// FailOn makes writes touching sub fail ("" disables).
func (f *Pihole) FailOn(sub string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failOn = sub
}

func (f *Pihole) check(s string) error {
	if f.failOn != "" && strings.Contains(s, f.failOn) {
		return errors.New("injected failure")
	}
	return nil
}

func dkey(d piholeapi.Domain) string { return d.Type + "|" + d.Kind + "|" + d.Domain }

func (f *Pihole) Lists(context.Context) ([]piholeapi.List, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.s.Lists), nil
}

func (f *Pihole) AddList(_ context.Context, l piholeapi.List) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	if err := f.check(l.Address); err != nil {
		return err
	}
	f.s.Lists = append(f.s.Lists, l)
	return nil
}

func (f *Pihole) UpdateList(_ context.Context, l piholeapi.List) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	for i := range f.s.Lists {
		if f.s.Lists[i].Address == l.Address && f.s.Lists[i].Type == l.Type {
			f.s.Lists[i] = l
		}
	}
	return nil
}

func (f *Pihole) DeleteList(_ context.Context, addr, typ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	f.s.Lists = slices.DeleteFunc(f.s.Lists, func(l piholeapi.List) bool { return l.Address == addr && l.Type == typ })
	return nil
}

func (f *Pihole) Domains(context.Context) ([]piholeapi.Domain, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.s.Domains), nil
}

func (f *Pihole) AddDomain(_ context.Context, d piholeapi.Domain) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	if err := f.check(d.Domain); err != nil {
		return err
	}
	f.s.Domains = append(f.s.Domains, d)
	return nil
}

func (f *Pihole) UpdateDomain(_ context.Context, d piholeapi.Domain) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	for i := range f.s.Domains {
		if dkey(f.s.Domains[i]) == dkey(d) {
			f.s.Domains[i] = d
		}
	}
	return nil
}

func (f *Pihole) DeleteDomain(_ context.Context, d piholeapi.Domain) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	f.s.Domains = slices.DeleteFunc(f.s.Domains, func(x piholeapi.Domain) bool { return dkey(x) == dkey(d) })
	return nil
}

func (f *Pihole) Groups(context.Context) ([]piholeapi.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.s.Groups), nil
}

func (f *Pihole) AddGroup(_ context.Context, name, comment string) (piholeapi.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	g := piholeapi.Group{Name: name, Comment: comment, Enabled: true, ID: len(f.s.Groups) + 10}
	f.s.Groups = append(f.s.Groups, g)
	return g, nil
}

func (f *Pihole) UpdateGroup(_ context.Context, g piholeapi.Group) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	for i := range f.s.Groups {
		if f.s.Groups[i].Name == g.Name {
			f.s.Groups[i].Comment, f.s.Groups[i].Enabled = g.Comment, g.Enabled
		}
	}
	return nil
}

// DeleteGroup removes the group and, like Pi-hole, every assignment to it.
func (f *Pihole) DeleteGroup(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	id := -1
	f.s.Groups = slices.DeleteFunc(f.s.Groups, func(g piholeapi.Group) bool {
		if g.Name == name {
			id = g.ID
			return true
		}
		return false
	})
	drop := func(ids []int) []int { return slices.DeleteFunc(ids, func(i int) bool { return i == id }) }
	for i := range f.s.Lists {
		f.s.Lists[i].Groups = drop(f.s.Lists[i].Groups)
	}
	for i := range f.s.Domains {
		f.s.Domains[i].Groups = drop(f.s.Domains[i].Groups)
	}
	for i := range f.s.Clients {
		f.s.Clients[i].Groups = drop(f.s.Clients[i].Groups)
	}
	return nil
}

func (f *Pihole) Clients(context.Context) ([]piholeapi.ClientEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.s.Clients), nil
}

func (f *Pihole) AddClient(_ context.Context, c piholeapi.ClientEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	if err := f.check(c.Client); err != nil {
		return err
	}
	f.s.Clients = append(f.s.Clients, c)
	return nil
}

func (f *Pihole) UpdateClient(_ context.Context, c piholeapi.ClientEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	for i := range f.s.Clients {
		if f.s.Clients[i].Client == c.Client {
			f.s.Clients[i] = c
		}
	}
	return nil
}

func (f *Pihole) DeleteClient(_ context.Context, client string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	f.s.Clients = slices.DeleteFunc(f.s.Clients, func(c piholeapi.ClientEntry) bool { return c.Client == client })
	return nil
}

func (f *Pihole) LocalRecords(context.Context) ([]string, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.s.Hosts), slices.Clone(f.s.CNAMEs), nil
}

func (f *Pihole) SetLocalRecords(_ context.Context, hosts, cnames []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.Writes++
	f.s.Hosts, f.s.CNAMEs = slices.Clone(hosts), slices.Clone(cnames)
	return nil
}

func (f *Pihole) RunGravity(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.s.GravityRuns++
	return nil
}
