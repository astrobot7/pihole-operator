// Package piholeapi is a minimal client for the Pi-hole v6 REST API.
package piholeapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// APIError is a non-2xx response from Pi-hole.
type APIError struct {
	Status  int
	Key     string
	Message string
	Hint    string
}

func (e *APIError) Error() string {
	if e.Hint != "" {
		return fmt.Sprintf("pihole api: %d %s: %s (%s)", e.Status, e.Key, e.Message, e.Hint)
	}
	return fmt.Sprintf("pihole api: %d %s: %s", e.Status, e.Key, e.Message)
}

// IsUnauthorized reports whether err is a 401 from Pi-hole.
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusUnauthorized
}

const (
	fieldComment = "comment"
	fieldType    = "type"
	fieldGroups  = "groups"
	fieldEnabled = "enabled"
)

// List is an adlist subscription.
type List struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
	Enabled bool   `json:"enabled"`
	ID      int    `json:"id,omitempty"`
}

// Domain is an exact or regex allow/deny entry.
type Domain struct {
	Domain  string `json:"domain"`
	Type    string `json:"type"` // allow | deny
	Kind    string `json:"kind"` // exact | regex
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
	Enabled bool   `json:"enabled"`
	ID      int    `json:"id,omitempty"`
}

// ClientEntry is a group assignment for an IP, CIDR, MAC, hostname or ":interface".
type ClientEntry struct {
	Client  string `json:"client"`
	Comment string `json:"comment"`
	Groups  []int  `json:"groups"`
	ID      int    `json:"id,omitempty"`
}

// Group is a Pi-hole group. ID 0 is the built-in Default group.
type Group struct {
	Name    string `json:"name"`
	Comment string `json:"comment"`
	Enabled bool   `json:"enabled"`
	ID      int    `json:"id"`
}

// Client talks to one Pi-hole instance. It keeps a single session and
// re-authenticates once on 401, so it never holds more than one of the
// instance's limited API sessions. Safe for concurrent use.
type Client struct {
	base     string
	password string
	hc       *http.Client

	mu  sync.Mutex
	sid string
}

// New returns a client for baseURL, e.g. "http://10.0.0.7:80".
func New(baseURL, password string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: strings.TrimRight(baseURL, "/") + "/api", password: password, hc: hc}
}

func (c *Client) login(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sid != "" {
		return c.sid, nil
	}
	var out struct {
		Session struct {
			Valid   bool   `json:"valid"`
			SID     string `json:"sid"`
			Message string `json:"message"`
		} `json:"session"`
	}
	if err := c.raw(ctx, http.MethodPost, "/auth", nil, map[string]string{"password": c.password}, "", &out); err != nil {
		return "", fmt.Errorf("login: %w", err)
	}
	if !out.Session.Valid || out.Session.SID == "" {
		return "", &APIError{Status: http.StatusUnauthorized, Key: "unauthorized", Message: out.Session.Message}
	}
	c.sid = out.Session.SID
	return c.sid, nil
}

func (c *Client) dropSession(sid string) {
	c.mu.Lock()
	if c.sid == sid {
		c.sid = ""
	}
	c.mu.Unlock()
}

// Logout ends the cached session, if any.
func (c *Client) Logout(ctx context.Context) error {
	c.mu.Lock()
	sid := c.sid
	c.sid = ""
	c.mu.Unlock()
	if sid == "" {
		return nil
	}
	return c.raw(ctx, http.MethodDelete, "/auth", nil, nil, sid, nil)
}

// do runs an authenticated request, retrying once with a fresh session on 401.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	for attempt := 0; ; attempt++ {
		sid, err := c.login(ctx)
		if err != nil {
			return err
		}
		err = c.raw(ctx, method, path, q, body, sid, out)
		if IsUnauthorized(err) && attempt == 0 {
			c.dropSession(sid)
			continue
		}
		return err
	}
}

func (c *Client) raw(ctx context.Context, method, path string, q url.Values, body any, sid string, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sid != "" {
		req.Header.Set("X-FTL-SID", sid)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		ae := &APIError{Status: resp.StatusCode}
		var eb struct {
			Error struct {
				Key     string `json:"key"`
				Message string `json:"message"`
				Hint    any    `json:"hint"`
			} `json:"error"`
		}
		if b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10)); json.Unmarshal(b, &eb) == nil {
			ae.Key, ae.Message = eb.Error.Key, eb.Error.Message
			if eb.Error.Hint != nil {
				ae.Hint = fmt.Sprint(eb.Error.Hint)
			}
		}
		return ae
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// processed is the per-item result Pi-hole returns for writes. A 2xx response
// can still carry item errors, e.g. a duplicate or invalid domain.
type processed struct {
	Processed *struct {
		Errors []struct {
			Item  string `json:"item"`
			Error string `json:"error"`
		} `json:"errors"`
	} `json:"processed"`
}

func (p processed) err() error {
	if p.Processed == nil || len(p.Processed.Errors) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(p.Processed.Errors))
	for _, e := range p.Processed.Errors {
		msgs = append(msgs, e.Item+": "+e.Error)
	}
	return &APIError{Status: http.StatusBadRequest, Key: "item_error", Message: strings.Join(msgs, "; ")}
}

// Lists returns every subscribed list.
func (c *Client) Lists(ctx context.Context) ([]List, error) {
	var out struct {
		Lists []List `json:"lists"`
	}
	return out.Lists, c.do(ctx, http.MethodGet, "/lists", nil, nil, &out)
}

// AddList subscribes to a list.
func (c *Client) AddList(ctx context.Context, l List) error {
	var p processed
	body := map[string]any{"address": l.Address, fieldComment: l.Comment, fieldGroups: l.Groups, fieldEnabled: l.Enabled}
	if err := c.do(ctx, http.MethodPost, "/lists", url.Values{fieldType: {l.Type}}, body, &p); err != nil {
		return err
	}
	return p.err()
}

// UpdateList changes an existing list's comment, groups or enabled flag.
func (c *Client) UpdateList(ctx context.Context, l List) error {
	var p processed
	body := map[string]any{fieldType: l.Type, fieldComment: l.Comment, fieldGroups: l.Groups, fieldEnabled: l.Enabled}
	if err := c.do(ctx, http.MethodPut, "/lists/"+url.PathEscape(l.Address), url.Values{fieldType: {l.Type}}, body, &p); err != nil {
		return err
	}
	return p.err()
}

// DeleteList removes a list.
func (c *Client) DeleteList(ctx context.Context, address, typ string) error {
	return c.do(ctx, http.MethodDelete, "/lists/"+url.PathEscape(address), url.Values{fieldType: {typ}}, nil, nil)
}

// Domains returns every allow/deny entry.
func (c *Client) Domains(ctx context.Context) ([]Domain, error) {
	var out struct {
		Domains []Domain `json:"domains"`
	}
	return out.Domains, c.do(ctx, http.MethodGet, "/domains", nil, nil, &out)
}

func domainPath(d Domain) string { return "/domains/" + d.Type + "/" + d.Kind }

// AddDomain creates an entry.
func (c *Client) AddDomain(ctx context.Context, d Domain) error {
	var p processed
	body := map[string]any{"domain": d.Domain, fieldComment: d.Comment, fieldGroups: d.Groups, fieldEnabled: d.Enabled}
	if err := c.do(ctx, http.MethodPost, domainPath(d), nil, body, &p); err != nil {
		return err
	}
	return p.err()
}

// UpdateDomain changes an existing entry's comment, groups or enabled flag.
func (c *Client) UpdateDomain(ctx context.Context, d Domain) error {
	var p processed
	body := map[string]any{fieldType: d.Type, "kind": d.Kind, fieldComment: d.Comment, fieldGroups: d.Groups, fieldEnabled: d.Enabled}
	if err := c.do(ctx, http.MethodPut, domainPath(d)+"/"+url.PathEscape(d.Domain), nil, body, &p); err != nil {
		return err
	}
	return p.err()
}

// DeleteDomain removes an entry.
func (c *Client) DeleteDomain(ctx context.Context, d Domain) error {
	return c.do(ctx, http.MethodDelete, domainPath(d)+"/"+url.PathEscape(d.Domain), nil, nil, nil)
}

// Groups returns every group, including Default (ID 0).
func (c *Client) Groups(ctx context.Context) ([]Group, error) {
	var out struct {
		Groups []Group `json:"groups"`
	}
	return out.Groups, c.do(ctx, http.MethodGet, "/groups", nil, nil, &out)
}

// AddGroup creates a group and returns it.
func (c *Client) AddGroup(ctx context.Context, name, comment string) (Group, error) {
	var out struct {
		processed
		Groups []Group `json:"groups"`
	}
	body := map[string]any{"name": name, fieldComment: comment, fieldEnabled: true}
	if err := c.do(ctx, http.MethodPost, "/groups", nil, body, &out); err != nil {
		return Group{}, err
	}
	if err := out.err(); err != nil {
		return Group{}, err
	}
	for _, g := range out.Groups {
		if g.Name == name {
			return g, nil
		}
	}
	return Group{}, fmt.Errorf("group %q not returned after create", name)
}

// UpdateGroup changes a group's comment and enabled flag.
func (c *Client) UpdateGroup(ctx context.Context, g Group) error {
	var p processed
	body := map[string]any{"name": g.Name, fieldComment: g.Comment, fieldEnabled: g.Enabled}
	if err := c.do(ctx, http.MethodPut, "/groups/"+url.PathEscape(g.Name), nil, body, &p); err != nil {
		return err
	}
	return p.err()
}

// DeleteGroup removes a group. Pi-hole also drops every assignment to it.
func (c *Client) DeleteGroup(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/groups/"+url.PathEscape(name), nil, nil, nil)
}

// Clients returns every client with a group assignment.
func (c *Client) Clients(ctx context.Context) ([]ClientEntry, error) {
	var out struct {
		Clients []ClientEntry `json:"clients"`
	}
	return out.Clients, c.do(ctx, http.MethodGet, "/clients", nil, nil, &out)
}

// AddClient creates a client assignment.
func (c *Client) AddClient(ctx context.Context, cl ClientEntry) error {
	var p processed
	body := map[string]any{"client": cl.Client, fieldComment: cl.Comment, fieldGroups: cl.Groups}
	if err := c.do(ctx, http.MethodPost, "/clients", nil, body, &p); err != nil {
		return err
	}
	return p.err()
}

// UpdateClient changes a client's comment and groups.
func (c *Client) UpdateClient(ctx context.Context, cl ClientEntry) error {
	var p processed
	body := map[string]any{fieldComment: cl.Comment, fieldGroups: cl.Groups}
	if err := c.do(ctx, http.MethodPut, "/clients/"+url.PathEscape(cl.Client), nil, body, &p); err != nil {
		return err
	}
	return p.err()
}

// DeleteClient removes a client assignment.
func (c *Client) DeleteClient(ctx context.Context, client string) error {
	return c.do(ctx, http.MethodDelete, "/clients/"+url.PathEscape(client), nil, nil, nil)
}

// LocalRecords returns dns.hosts ("IP host") and dns.cnameRecords ("host,target[,ttl]").
func (c *Client) LocalRecords(ctx context.Context) (hosts, cnames []string, err error) {
	var out struct {
		Config struct {
			DNS struct {
				Hosts        []string `json:"hosts"`
				CNAMERecords []string `json:"cnameRecords"`
			} `json:"dns"`
		} `json:"config"`
	}
	// /config/dns returns the whole dns section in one call.
	if err := c.do(ctx, http.MethodGet, "/config/dns", nil, nil, &out); err != nil {
		return nil, nil, err
	}
	return out.Config.DNS.Hosts, out.Config.DNS.CNAMERecords, nil
}

// SetLocalRecords replaces dns.hosts and dns.cnameRecords.
func (c *Client) SetLocalRecords(ctx context.Context, hosts, cnames []string) error {
	if hosts == nil {
		hosts = []string{}
	}
	if cnames == nil {
		cnames = []string{}
	}
	body := map[string]any{"config": map[string]any{"dns": map[string]any{"hosts": hosts, "cnameRecords": cnames}}}
	return c.do(ctx, http.MethodPatch, "/config", nil, body, nil)
}

// RunGravity rebuilds the gravity database and blocks until Pi-hole finishes
// streaming its output. Callers should pass a context with a generous timeout.
func (c *Client) RunGravity(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/action/gravity", nil, nil, nil)
}
