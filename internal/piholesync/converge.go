package piholesync

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/astrobot7/pihole-operator/internal/piholeapi"
)

// API is the subset of the Pi-hole client the sync engine needs.
type API interface {
	Lists(ctx context.Context) ([]piholeapi.List, error)
	AddList(ctx context.Context, l piholeapi.List) error
	UpdateList(ctx context.Context, l piholeapi.List) error
	DeleteList(ctx context.Context, address, typ string) error
	Domains(ctx context.Context) ([]piholeapi.Domain, error)
	AddDomain(ctx context.Context, d piholeapi.Domain) error
	UpdateDomain(ctx context.Context, d piholeapi.Domain) error
	DeleteDomain(ctx context.Context, d piholeapi.Domain) error
	Groups(ctx context.Context) ([]piholeapi.Group, error)
	AddGroup(ctx context.Context, name, comment string) (piholeapi.Group, error)
	UpdateGroup(ctx context.Context, g piholeapi.Group) error
	DeleteGroup(ctx context.Context, name string) error
	Clients(ctx context.Context) ([]piholeapi.ClientEntry, error)
	AddClient(ctx context.Context, c piholeapi.ClientEntry) error
	UpdateClient(ctx context.Context, c piholeapi.ClientEntry) error
	DeleteClient(ctx context.Context, client string) error
	LocalRecords(ctx context.Context) (hosts, cnames []string, err error)
	SetLocalRecords(ctx context.Context, hosts, cnames []string) error
}

// Options control pruning.
type Options struct {
	// PruneAll deletes every list and domain not in Desired, including
	// entries added by hand. When false only Marker-tagged entries are pruned.
	PruneAll bool
	// PreviousHosts and PreviousCNAMEs are the records the operator applied
	// last time. Local records carry no comment, so this is how the operator
	// tells its own stale records from hand-made ones under ManagedOnly.
	PreviousHosts  []string
	PreviousCNAMEs []string
}

// Result reports what Converge changed.
type Result struct {
	Changes int
	// ListsChanged is true when lists were added or removed, which means the
	// pod needs a gravity rebuild before the change takes effect.
	ListsChanged bool
}

// Converge makes one Pi-hole match d. It keeps going after individual item
// failures and returns them joined, so one bad domain does not block the rest.
func Converge(ctx context.Context, api API, d Desired, opt Options) (Result, error) {
	var res Result
	var errs []error

	ids, live, err := ensureGroups(ctx, api, d, &res)
	if err != nil {
		return res, fmt.Errorf("groups: %w", err)
	}

	if err := convergeLists(ctx, api, d.Lists, ids, opt, &res); err != nil {
		errs = append(errs, err)
	}
	if err := convergeDomains(ctx, api, d.Domains, ids, opt, &res); err != nil {
		errs = append(errs, err)
	}
	if err := convergeClients(ctx, api, d.Clients, ids, opt, &res); err != nil {
		errs = append(errs, err)
	}
	if err := convergeRecords(ctx, api, d, opt, &res); err != nil {
		errs = append(errs, err)
	}
	// Groups go last: by now nothing desired points at a group being removed.
	if len(errs) == 0 {
		if err := pruneGroups(ctx, api, d, live, opt, &res); err != nil {
			errs = append(errs, err)
		}
	}
	return res, errors.Join(errs...)
}

// ensureGroups creates missing groups, brings declared groups' comment and
// enabled flag in line, and returns name->ID plus the live groups.
func ensureGroups(ctx context.Context, api API, d Desired, res *Result) (map[string]int, []piholeapi.Group, error) {
	live, err := api.Groups(ctx)
	if err != nil {
		return nil, nil, err
	}
	ids := map[string]int{DefaultGroup: 0}
	byName := map[string]piholeapi.Group{}
	for _, g := range live {
		ids[g.Name] = g.ID
		byName[g.Name] = g
	}
	defs := map[string]GroupDef{}
	for _, g := range d.GroupDefs {
		defs[g.Name] = g
	}
	for _, name := range d.Groups() {
		def, declared := defs[name]
		cur, exists := byName[name]
		if !exists {
			c := "[" + Marker + "]"
			if declared {
				c = def.Comment
			}
			g, err := api.AddGroup(ctx, name, c)
			if err != nil {
				return nil, nil, fmt.Errorf("create %q: %w", name, err)
			}
			ids[name] = g.ID
			res.Changes++
			cur = g
		}
		if declared && (cur.Comment != def.Comment || cur.Enabled != def.Enabled) {
			if err := api.UpdateGroup(ctx, piholeapi.Group{Name: name, Comment: def.Comment, Enabled: def.Enabled, ID: cur.ID}); err != nil {
				return nil, nil, fmt.Errorf("update %q: %w", name, err)
			}
			res.Changes++
		}
	}
	return ids, live, nil
}

func pruneGroups(ctx context.Context, api API, d Desired, live []piholeapi.Group, opt Options, res *Result) error {
	want := map[string]bool{}
	for _, g := range d.Groups() {
		want[g] = true
	}
	var errs []error
	for _, g := range live {
		if g.ID == 0 || want[g.Name] || !prunable(g.Comment, opt) {
			continue
		}
		if err := api.DeleteGroup(ctx, g.Name); err != nil {
			errs = append(errs, fmt.Errorf("delete group %s: %w", g.Name, err))
			continue
		}
		res.Changes++
	}
	return errors.Join(errs...)
}

func convergeClients(ctx context.Context, api API, want []Client, ids map[string]int, opt Options, res *Result) error {
	live, err := api.Clients(ctx)
	if err != nil {
		return fmt.Errorf("clients: %w", err)
	}
	have := map[string]piholeapi.ClientEntry{}
	for _, c := range live {
		have[c.Client] = c
	}
	var errs []error
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w.Client] = true
		target := piholeapi.ClientEntry{Client: w.Client, Comment: w.Comment, Groups: resolve(w.Groups, ids)}
		cur, ok := have[w.Client]
		switch {
		case !ok:
			if err := api.AddClient(ctx, target); err != nil {
				errs = append(errs, fmt.Errorf("add client %s: %w", w.Client, err))
				continue
			}
			res.Changes++
		case cur.Comment != target.Comment || !sameInts(cur.Groups, target.Groups):
			if err := api.UpdateClient(ctx, target); err != nil {
				errs = append(errs, fmt.Errorf("update client %s: %w", w.Client, err))
				continue
			}
			res.Changes++
		}
	}
	for k, c := range have {
		if wanted[k] || !prunable(c.Comment, opt) {
			continue
		}
		if err := api.DeleteClient(ctx, c.Client); err != nil {
			errs = append(errs, fmt.Errorf("delete client %s: %w", c.Client, err))
			continue
		}
		res.Changes++
	}
	return errors.Join(errs...)
}

func resolve(names []string, ids map[string]int) []int {
	out := make([]int, 0, len(names))
	for _, n := range names {
		out = append(out, ids[n])
	}
	slices.Sort(out)
	return out
}

func sameInts(a, b []int) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func prunable(comment string, opt Options) bool {
	return opt.PruneAll || strings.Contains(comment, Marker)
}

func convergeLists(ctx context.Context, api API, want []List, ids map[string]int, opt Options, res *Result) error {
	live, err := api.Lists(ctx)
	if err != nil {
		return fmt.Errorf("lists: %w", err)
	}
	have := map[string]piholeapi.List{}
	for _, l := range live {
		have[listKey(l.Address, l.Type)] = l
	}
	var errs []error
	wanted := map[string]bool{}
	for _, w := range want {
		k := listKey(w.Address, w.Type)
		wanted[k] = true
		target := piholeapi.List{Address: w.Address, Type: w.Type, Comment: w.Comment, Enabled: w.Enabled, Groups: resolve(w.Groups, ids)}
		cur, ok := have[k]
		switch {
		case !ok:
			if err := api.AddList(ctx, target); err != nil {
				errs = append(errs, fmt.Errorf("add list %s: %w", w.Address, err))
				continue
			}
			res.Changes++
			res.ListsChanged = true
		case cur.Comment != target.Comment || cur.Enabled != target.Enabled || !sameInts(cur.Groups, target.Groups):
			if err := api.UpdateList(ctx, target); err != nil {
				errs = append(errs, fmt.Errorf("update list %s: %w", w.Address, err))
				continue
			}
			res.Changes++
		}
	}
	for k, l := range have {
		if wanted[k] || !prunable(l.Comment, opt) {
			continue
		}
		if err := api.DeleteList(ctx, l.Address, l.Type); err != nil {
			errs = append(errs, fmt.Errorf("delete list %s: %w", l.Address, err))
			continue
		}
		res.Changes++
		res.ListsChanged = true
	}
	return errors.Join(errs...)
}

func convergeDomains(ctx context.Context, api API, want []Domain, ids map[string]int, opt Options, res *Result) error {
	live, err := api.Domains(ctx)
	if err != nil {
		return fmt.Errorf("domains: %w", err)
	}
	have := map[string]piholeapi.Domain{}
	for _, d := range live {
		have[domainKey(d.Domain, d.Type, d.Kind)] = d
	}
	var errs []error
	wanted := map[string]bool{}
	for _, w := range want {
		k := domainKey(w.Domain, w.Type, w.Kind)
		wanted[k] = true
		target := piholeapi.Domain{Domain: w.Domain, Type: w.Type, Kind: w.Kind, Comment: w.Comment, Enabled: w.Enabled, Groups: resolve(w.Groups, ids)}
		cur, ok := have[k]
		switch {
		case !ok:
			if err := api.AddDomain(ctx, target); err != nil {
				errs = append(errs, fmt.Errorf("add domain %s: %w", w.Domain, err))
				continue
			}
			res.Changes++
		case cur.Comment != target.Comment || cur.Enabled != target.Enabled || !sameInts(cur.Groups, target.Groups):
			if err := api.UpdateDomain(ctx, target); err != nil {
				errs = append(errs, fmt.Errorf("update domain %s: %w", w.Domain, err))
				continue
			}
			res.Changes++
		}
	}
	for k, d := range have {
		if wanted[k] || !prunable(d.Comment, opt) {
			continue
		}
		if err := api.DeleteDomain(ctx, d); err != nil {
			errs = append(errs, fmt.Errorf("delete domain %s: %w", d.Domain, err))
			continue
		}
		res.Changes++
	}
	return errors.Join(errs...)
}

// mergeRecords keeps hand-made live records (unless pruneAll), drops records
// the operator applied previously but no longer wants, and adds desired ones.
func mergeRecords(live, previous, want []string, pruneAll bool) []string {
	set := map[string]struct{}{}
	if !pruneAll {
		prev := map[string]struct{}{}
		for _, p := range previous {
			prev[p] = struct{}{}
		}
		for _, l := range live {
			if _, mine := prev[l]; !mine {
				set[l] = struct{}{}
			}
		}
	}
	for _, w := range want {
		set[w] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func convergeRecords(ctx context.Context, api API, d Desired, opt Options, res *Result) error {
	hosts, cnames, err := api.LocalRecords(ctx)
	if err != nil {
		return fmt.Errorf("local records: %w", err)
	}
	newHosts := mergeRecords(hosts, opt.PreviousHosts, d.Hosts, opt.PruneAll)
	newCNAMEs := mergeRecords(cnames, opt.PreviousCNAMEs, d.CNAMEs, opt.PruneAll)
	if equalSet(hosts, newHosts) && equalSet(cnames, newCNAMEs) {
		return nil
	}
	if err := api.SetLocalRecords(ctx, newHosts, newCNAMEs); err != nil {
		return fmt.Errorf("set local records: %w", err)
	}
	res.Changes++
	return nil
}

func equalSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
