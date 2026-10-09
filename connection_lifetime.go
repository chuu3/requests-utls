package requestsutls

import (
	h2 "github.com/chuu3/requests-utls/internal/h2"
	"math/rand/v2"
	"net"
	"time"
)

// ErrConnectionExpired means a new connection exhausted its lifetime before
// it could be used. No HTTP request was sent; we do not redial indefinitely.
var ErrConnectionExpired = h2.ErrConnectionExpired

func (s *Session) newConnectionLifetime() (time.Time, time.Time) {
	created := time.Now() // retains the monotonic clock through Add
	if s.maxConnectionAge == 0 {
		return created, time.Time{}
	}
	offset := time.Duration(0)
	if s.connectionAgeJitter > 0 {
		offset = time.Duration(rand.Int64N(int64(s.connectionAgeJitter)))
	}
	return created, created.Add(s.maxConnectionAge - offset)
}

func connectionRetireAt(conn net.Conn) time.Time {
	if c, ok := conn.(*trackedConn); ok {
		return c.retireAt
	}
	if c, ok := conn.(interface{ NetConn() net.Conn }); ok {
		return connectionRetireAt(c.NetConn())
	}
	return time.Time{}
}

func connectionExpired(conn net.Conn) bool {
	deadline := connectionRetireAt(conn)
	return !deadline.IsZero() && !time.Now().Before(deadline)
}
