// Package piholesync computes the desired Pi-hole configuration from CRs and
// converges a single Pi-hole instance towards it.
package piholesync

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/astrobot7/pihole-operator/api/v1alpha1"
)

// Marker is embedded in the comment of every list and domain the operator
// creates. Entries without it are left alone under PrunePolicy ManagedOnly.
const Marker = "managed by pihole-operator"

// DefaultGroup is Pi-hole's built-in group (ID 0).
const DefaultGroup = "Default"

// List is a desired adlist with group names (resolved to IDs per pod).
type List struct {
	Address string
	Type    string
	Comment string
	Enabled bool
	Groups  []string
}

// Domain is a desired allow/deny entry with group names.
type Domain struct {
	Domain  string
	Type    string // allow | deny
	Kind    string // exact | regex
	Comment string
	Enabled bool
	Groups  []string
}

// GroupDef is a group declared by a PiholeGroup.
type GroupDef struct {
	Name    string
	Comment string
	Enabled bool
}

// Client is a desired client-to-group assignment.
type Client struct {
	Client  string
	Comment string
	Groups  []string
}

// Desired is the full configuration every replica of a cluster should have.
// Slices are sorted so the struct hashes deterministically.
type Desired struct {
	GroupDefs []GroupDef
	Lists     []List
	Domains   []Domain
	Clients   []Client
	Hosts     []string // "IP host"
	CNAMEs    []string // "host,target[,ttl]"
}

// Hash returns a stable fingerprint of d.
func (d Desired) Hash() string {
	b, _ := json.Marshal(d)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

// Groups returns every non-default group name declared or referenced by d.
func (d Desired) Groups() []string {
	set := map[string]struct{}{}
	for _, g := range d.GroupDefs {
		set[g.Name] = struct{}{}
	}
	for _, c := range d.Clients {
		for _, g := range c.Groups {
			set[g] = struct{}{}
		}
	}
	for _, l := range d.Lists {
		for _, g := range l.Groups {
			set[g] = struct{}{}
		}
	}
	for _, x := range d.Domains {
		for _, g := range x.Groups {
			set[g] = struct{}{}
		}
	}
	delete(set, DefaultGroup)
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	slices.Sort(out)
	return out
}

func comment(user, ns, name string) string {
	tag := fmt.Sprintf("[%s: %s/%s]", Marker, ns, name)
	if user = strings.TrimSpace(user); user == "" {
		return tag
	}
	return user + " " + tag
}

func groupsOrDefault(gs []string) []string {
	if len(gs) == 0 {
		return []string{DefaultGroup}
	}
	out := slices.Clone(gs)
	slices.Sort(out)
	return slices.Compact(out)
}

// enabled treats an unset flag as true, matching the CRD default.
func enabled(p *bool) bool { return p == nil || *p }

func listKey(addr, typ string) string      { return typ + "|" + addr }
func domainKey(d, typ, kind string) string { return typ + "|" + kind + "|" + d }
func mergeGroups(a, b []string) []string   { return groupsOrDefault(append(slices.Clone(a), b...)) }
func sortedByName[T interface {
	GetNamespace() string
	GetName() string
}](xs []T) {
	slices.SortFunc(xs, func(a, b T) int {
		return strings.Compare(a.GetNamespace()+"/"+a.GetName(), b.GetNamespace()+"/"+b.GetName())
	})
}

// Build merges all child CRs of one cluster into a Desired state. When the
// same list or domain appears in several objects, groups are unioned, the
// entry is enabled if any object enables it, and the comment comes from the
// first object by namespace/name.
func Build(blocklists []v1alpha1.PiholeBlocklist, domainLists []v1alpha1.PiholeDomainList,
	records []v1alpha1.PiholeLocalRecord, groups []v1alpha1.PiholeGroup) Desired {
	bl := ptrs(blocklists)
	dl := ptrs(domainLists)
	lr := ptrs(records)
	gs := ptrs(groups)
	sortedByName(bl)
	sortedByName(dl)
	sortedByName(lr)
	sortedByName(gs)

	var d Desired
	d.GroupDefs, d.Clients = buildGroups(gs)

	lists := map[string]*List{}
	var listOrder []string
	for _, b := range bl {
		typ := string(b.Spec.Type)
		if typ == "" {
			typ = string(v1alpha1.ListTypeBlock)
		}
		for _, src := range b.Spec.Lists {
			k := listKey(src.URL, typ)
			if cur, ok := lists[k]; ok {
				cur.Enabled = cur.Enabled || enabled(src.Enabled)
				cur.Groups = mergeGroups(cur.Groups, b.Spec.Groups)
				continue
			}
			lists[k] = &List{
				Address: src.URL, Type: typ,
				Comment: comment(src.Comment, b.Namespace, b.Name),
				Enabled: enabled(src.Enabled),
				Groups:  groupsOrDefault(b.Spec.Groups),
			}
			listOrder = append(listOrder, k)
		}
	}
	slices.Sort(listOrder)
	for _, k := range listOrder {
		d.Lists = append(d.Lists, *lists[k])
	}

	domains := map[string]*Domain{}
	var domOrder []string
	for _, x := range dl {
		for _, e := range x.Spec.Entries {
			kind := string(e.Kind)
			if kind == "" {
				kind = string(v1alpha1.DomainKindExact)
			}
			name := e.Domain
			if kind == string(v1alpha1.DomainKindExact) {
				name = strings.ToLower(strings.TrimSuffix(name, ".")) // Pi-hole stores exact domains lowercased
			}
			k := domainKey(name, string(e.Action), kind)
			if cur, ok := domains[k]; ok {
				cur.Enabled = cur.Enabled || enabled(e.Enabled)
				cur.Groups = mergeGroups(cur.Groups, x.Spec.Groups)
				continue
			}
			domains[k] = &Domain{
				Domain: name, Type: string(e.Action), Kind: kind,
				Comment: comment(e.Comment, x.Namespace, x.Name),
				Enabled: enabled(e.Enabled),
				Groups:  groupsOrDefault(x.Spec.Groups),
			}
			domOrder = append(domOrder, k)
		}
	}
	slices.Sort(domOrder)
	for _, k := range domOrder {
		d.Domains = append(d.Domains, *domains[k])
	}

	for _, r := range lr {
		for _, a := range r.Spec.A {
			d.Hosts = append(d.Hosts, a.IP+" "+a.Host)
		}
		for _, c := range r.Spec.CNAME {
			s := c.Host + "," + c.Target
			if c.TTL > 0 {
				s += fmt.Sprintf(",%d", c.TTL)
			}
			d.CNAMEs = append(d.CNAMEs, s)
		}
	}
	slices.Sort(d.Hosts)
	d.Hosts = slices.Compact(d.Hosts)
	slices.Sort(d.CNAMEs)
	d.CNAMEs = slices.Compact(d.CNAMEs)
	return d
}

var macRe = regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$`)

// normalizeClient trims the identifier and upper-cases MAC addresses, which
// is how the Pi-hole web UI stores them.
func normalizeClient(c string) string {
	c = strings.TrimSpace(c)
	if macRe.MatchString(c) {
		return strings.ToUpper(strings.ReplaceAll(c, "-", ":"))
	}
	return c
}

// buildGroups merges PiholeGroups. Groups with the same Pi-hole name merge
// (enabled if any is enabled, comment from the first). A client's groups are
// every group listing it, plus Default unless all of those groups set
// excludeFromDefault.
func buildGroups(gs []*v1alpha1.PiholeGroup) ([]GroupDef, []Client) {
	defs := map[string]*GroupDef{}
	type member struct {
		groups      []string
		keepDefault bool
		comment     string
	}
	members := map[string]*member{}
	for _, g := range gs {
		name := g.GroupName()
		if name != DefaultGroup {
			if cur, ok := defs[name]; ok {
				cur.Enabled = cur.Enabled || enabled(g.Spec.Enabled)
			} else {
				defs[name] = &GroupDef{Name: name, Comment: comment(g.Spec.Description, g.Namespace, g.Name), Enabled: enabled(g.Spec.Enabled)}
			}
		}
		for _, raw := range g.Spec.Clients {
			c := normalizeClient(raw)
			if c == "" {
				continue
			}
			m, ok := members[c]
			if !ok {
				m = &member{comment: comment("", g.Namespace, g.Name)}
				members[c] = m
			}
			m.groups = append(m.groups, name)
			if name == DefaultGroup || !g.Spec.ExcludeFromDefault {
				m.keepDefault = true
			}
		}
	}

	outDefs := make([]GroupDef, 0, len(defs))
	for _, g := range defs {
		outDefs = append(outDefs, *g)
	}
	slices.SortFunc(outDefs, func(a, b GroupDef) int { return strings.Compare(a.Name, b.Name) })

	outClients := make([]Client, 0, len(members))
	for c, m := range members {
		groups := m.groups
		if m.keepDefault {
			groups = append(groups, DefaultGroup)
		}
		groups = slices.Clone(groups)
		slices.Sort(groups)
		outClients = append(outClients, Client{Client: c, Comment: m.comment, Groups: slices.Compact(groups)})
	}
	slices.SortFunc(outClients, func(a, b Client) int { return strings.Compare(a.Client, b.Client) })
	return outDefs, outClients
}

func ptrs[T any](xs []T) []*T {
	out := make([]*T, len(xs))
	for i := range xs {
		out[i] = &xs[i]
	}
	return out
}
