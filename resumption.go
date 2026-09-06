package requestsutls

import (
	"slices"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// uTLS v1.8.2 exposes this limitation as an untyped error. Match its exact
// message only; other TLS errors must never cause a full-handshake retry.
const utlsPSKHelloRetryError = "uTLS does not support reprocessing of PSK key triggered by HelloRetryRequest"

// Dropping the backing cache on Close releases ticket secrets even if callers
// retain a closed Session. Late TLS reader callbacks cannot repopulate it.
type sessionTicketCache struct {
	mu    sync.Mutex
	cache utls.ClientSessionCache
}

func (c *sessionTicketCache) Get(key string) (*utls.ClientSessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		return nil, false
	}
	return c.cache.Get(key)
}

func (c *sessionTicketCache) Put(key string, state *utls.ClientSessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache != nil {
		c.cache.Put(key, state)
	}
}

func (c *sessionTicketCache) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = nil
}

// authoritySessionCache adds the port to uTLS's ServerName-only cache key.
// Each view belongs to one connection; its shared backing LRU is concurrent.
type authoritySessionCache struct {
	cache     utls.ClientSessionCache
	authority string
	skipRead  bool
}

func (c authoritySessionCache) Get(key string) (*utls.ClientSessionState, bool) {
	if c.skipRead {
		return nil, false
	}
	return c.cache.Get(c.authority + "\x00" + key)
}

func (c authoritySessionCache) Put(key string, state *utls.ClientSessionState) {
	// uTLS drops a failed resumption's ticket through Put(key, nil), including
	// the PSK+HRR path. Successful full-handshake fallback stores fresh tickets.
	c.cache.Put(c.authority+"\x00"+key, state)
}

func configureResumption(config *utls.Config, spec *utls.ClientHelloSpec, cache *sessionTicketCache, authority string, skipRead bool) {
	if cache == nil {
		return
	}
	hasTicket, hasDHEMode := false, false
	for _, extension := range spec.Extensions {
		switch extension := extension.(type) {
		case *utls.SessionTicketExtension:
			hasTicket = true
		case *utls.PSKKeyExchangeModesExtension:
			hasDHEMode = slices.Contains(extension.Modes, uint8(1))
		}
	}
	hasPSK := spec.TLSVersMax >= utls.VersionTLS13 && hasDHEMode
	if !hasTicket && !hasPSK {
		return
	}
	if hasPSK {
		// Empty PSK has zero wire length, preserving the first ClientHello.
		// With a valid ticket, uTLS creates fresh identities and binders. The
		// extension must be last, even after trailing GREASE or padding.
		spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
	}
	config.SessionTicketsDisabled = false
	config.ClientSessionCache = authoritySessionCache{cache: cache, authority: authority, skipRead: skipRead}
	config.OmitEmptyPsk = true
	config.PreferSkipResumptionOnNilExtension = true
}
