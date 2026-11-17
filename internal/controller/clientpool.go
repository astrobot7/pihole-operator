package controller

import (
	"context"
	"net"
	"strconv"
	"sync"

	"github.com/astrobot7/pihole-operator/internal/piholeapi"
	"github.com/astrobot7/pihole-operator/internal/piholesync"
)

// ClientFactory builds an API client for one pod. Tests swap it for a fake.
type ClientFactory func(baseURL, password string) piholesync.API

type poolKey struct {
	cluster  string // namespace/name
	podUID   string
	podIP    string
	passHash string
}

// clientPool caches one API client (and so one Pi-hole session) per pod
// incarnation and password. A restarted pod gets a new UID and a new client.
type clientPool struct {
	mu      sync.Mutex
	factory ClientFactory
	clients map[poolKey]piholesync.API
}

func newClientPool(f ClientFactory) *clientPool {
	if f == nil {
		f = func(u, p string) piholesync.API { return piholeapi.New(u, p, nil) }
	}
	return &clientPool{factory: f, clients: map[poolKey]piholesync.API{}}
}

func (p *clientPool) get(k poolKey, password string) piholesync.API {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c, ok := p.clients[k]; ok {
		return c
	}
	c := p.factory("http://"+net.JoinHostPort(k.podIP, strconv.Itoa(webPort)), password)
	p.clients[k] = c
	return c
}

// retain drops a cluster's clients whose key is not in keep, logging out where possible.
func (p *clientPool) retain(ctx context.Context, cluster string, keep map[poolKey]bool) {
	p.mu.Lock()
	var stale []piholesync.API
	for k, c := range p.clients {
		if k.cluster == cluster && !keep[k] {
			stale = append(stale, c)
			delete(p.clients, k)
		}
	}
	p.mu.Unlock()
	for _, c := range stale {
		if lo, ok := c.(interface{ Logout(context.Context) error }); ok {
			_ = lo.Logout(ctx)
		}
	}
}
