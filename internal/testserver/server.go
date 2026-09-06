// Package testserver provides a local HTTP/2 peer that exposes wire ordering.
// It deliberately avoids net/http's map-based representation of headers.
package testserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type Request struct {
	Connection int
	DidResume  bool
	StreamID   uint32
	Headers    []hpack.HeaderField
	Body       []byte
}

func (r Request) Header(name string) string {
	for _, field := range r.Headers {
		if field.Name == name {
			return field.Value
		}
	}
	return ""
}

type Response struct {
	Status  string
	Headers []hpack.HeaderField
	Body    []byte
	// GoAway retires this connection before completing the response. Use this
	// only with one active stream when a test needs a deterministic reconnect.
	GoAway bool
}

type Handler func(context.Context, Request) Response

type WindowUpdate struct {
	StreamID uint32
	Amount   uint32
}

type Priority struct {
	StreamID uint32
	Param    http2.PriorityParam
}

type Snapshot struct {
	Connections      int
	ClientHellos     [][]byte
	Settings         [][]http2.Setting
	Windows          []WindowUpdate
	Priorities       []Priority
	HeaderPriorities []Priority
	Requests         []Request
	ResetStreams     []uint32
}

type Server struct {
	URL         string
	RootCAs     *x509.CertPool
	Certificate *x509.Certificate

	listener   net.Listener
	tlsConfig  *tls.Config
	handler    Handler
	acceptDone chan struct{}
	connWG     sync.WaitGroup
	closeOnce  sync.Once
	mu         sync.Mutex
	conns      map[net.Conn]struct{}
	snapshot   Snapshot
}

func New(handler Handler) (*Server, error) {
	return NewWithALPN(handler, []string{"h2"})
}

func NewWithALPN(handler Handler, protocols []string) (*Server, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	parsedCertificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	s := &Server{
		URL: "https://localhost:" + port, RootCAs: roots, Certificate: parsedCertificate,
		listener: listener, handler: handler, acceptDone: make(chan struct{}), conns: make(map[net.Conn]struct{}),
		tlsConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, NextProtos: protocols, MinVersion: tls.VersionTLS12},
	}
	go s.accept()
	return s, nil
}

func (s *Server) Close() {
	s.closeOnce.Do(func() {
		s.listener.Close()
		<-s.acceptDone
		s.mu.Lock()
		for conn := range s.conns {
			conn.Close()
		}
		s.mu.Unlock()
		s.connWG.Wait()
	})
}

func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.snapshot
	out.ClientHellos = append([][]byte(nil), out.ClientHellos...)
	out.Settings = append([][]http2.Setting(nil), out.Settings...)
	out.Windows = append([]WindowUpdate(nil), out.Windows...)
	out.Priorities = append([]Priority(nil), out.Priorities...)
	out.HeaderPriorities = append([]Priority(nil), out.HeaderPriorities...)
	out.Requests = append([]Request(nil), out.Requests...)
	out.ResetStreams = append([]uint32(nil), out.ResetStreams...)
	return out
}

func (s *Server) accept() {
	defer close(s.acceptDone)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[conn] = struct{}{}
		s.snapshot.Connections++
		id := s.snapshot.Connections
		s.mu.Unlock()
		s.connWG.Add(1)
		go func() {
			defer s.connWG.Done()
			defer conn.Close()
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
			}()
			s.serve(conn, id)
		}()
	}
}

type captureConn struct {
	net.Conn
	bytes []byte
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.bytes = append(c.bytes, p[:n]...)
	return n, err
}

func (s *Server) serve(raw net.Conn, connection int) {
	captured := &captureConn{Conn: raw}
	conn := tls.Server(captured, s.tlsConfig)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		return
	}
	state := conn.ConnectionState()
	s.mu.Lock()
	s.snapshot.ClientHellos = append(s.snapshot.ClientHellos, append([]byte(nil), captured.bytes...))
	s.mu.Unlock()
	if state.NegotiatedProtocol != "h2" {
		return
	}
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil || string(preface) != http2.ClientPreface {
		return
	}
	framer := http2.NewFramer(conn, conn)
	framer.ReadMetaHeaders = hpack.NewDecoder(65536, nil)
	var writeMu sync.Mutex
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: 256}); err != nil {
		return
	}
	var buffer bytes.Buffer
	encoder := hpack.NewEncoder(&buffer)
	streams := make(map[uint32]*Request)
	cancels := make(map[uint32]context.CancelFunc)
	var handlers sync.WaitGroup
	defer func() {
		cancel()
		raw.Close()
		handlers.Wait()
	}()
	dispatch := func(req Request) {
		requestCtx, requestCancel := context.WithCancel(ctx)
		cancels[req.StreamID] = requestCancel
		s.mu.Lock()
		s.snapshot.Requests = append(s.snapshot.Requests, req)
		s.mu.Unlock()
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer requestCancel()
			response := Response{Body: []byte("ok")}
			if s.handler != nil {
				response = s.handler(requestCtx, req)
			}
			if requestCtx.Err() != nil {
				return
			}
			if response.Status == "" {
				response.Status = "200"
			}
			writeMu.Lock()
			defer writeMu.Unlock()
			if response.GoAway {
				// The client must observe retirement before END_STREAM makes
				// this request complete and permits the next sequential request.
				if err := framer.WriteGoAway(req.StreamID, http2.ErrCodeNo, nil); err != nil {
					return
				}
				defer raw.Close()
			}
			buffer.Reset()
			encoder.WriteField(hpack.HeaderField{Name: ":status", Value: response.Status})
			for _, field := range response.Headers {
				encoder.WriteField(field)
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: req.StreamID, BlockFragment: buffer.Bytes(), EndHeaders: true, EndStream: len(response.Body) == 0}); err != nil {
				return
			}
			// Responses used by these tests fit in the initial stream window.
			for body := response.Body; len(body) > 0; {
				n := len(body)
				if n > 16384 {
					n = 16384
				}
				if err := framer.WriteData(req.StreamID, n == len(body), body[:n]); err != nil {
					return
				}
				body = body[n:]
			}
		}()
	}
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if frame.IsAck() {
				continue
			}
			var settings []http2.Setting
			frame.ForeachSetting(func(setting http2.Setting) error { settings = append(settings, setting); return nil })
			s.mu.Lock()
			s.snapshot.Settings = append(s.snapshot.Settings, settings)
			s.mu.Unlock()
			writeMu.Lock()
			err = framer.WriteSettingsAck()
			writeMu.Unlock()
			if err != nil {
				return
			}
		case *http2.WindowUpdateFrame:
			s.mu.Lock()
			s.snapshot.Windows = append(s.snapshot.Windows, WindowUpdate{StreamID: frame.Header().StreamID, Amount: frame.Increment})
			s.mu.Unlock()
		case *http2.PriorityFrame:
			s.mu.Lock()
			s.snapshot.Priorities = append(s.snapshot.Priorities, Priority{StreamID: frame.Header().StreamID, Param: frame.PriorityParam})
			s.mu.Unlock()
		case *http2.MetaHeadersFrame:
			if frame.HasPriority() {
				s.mu.Lock()
				s.snapshot.HeaderPriorities = append(s.snapshot.HeaderPriorities, Priority{StreamID: frame.Header().StreamID, Param: frame.Priority})
				s.mu.Unlock()
			}
			req := &Request{Connection: connection, DidResume: state.DidResume, StreamID: frame.Header().StreamID, Headers: append([]hpack.HeaderField(nil), frame.Fields...)}
			streams[req.StreamID] = req
			if frame.StreamEnded() {
				dispatch(*req)
				delete(streams, req.StreamID)
			}
		case *http2.DataFrame:
			req := streams[frame.Header().StreamID]
			if req == nil {
				return
			}
			req.Body = append(req.Body, frame.Data()...)
			if frame.StreamEnded() {
				dispatch(*req)
				delete(streams, req.StreamID)
			}
		case *http2.RSTStreamFrame:
			if streamCancel := cancels[frame.Header().StreamID]; streamCancel != nil {
				streamCancel()
			}
			s.mu.Lock()
			s.snapshot.ResetStreams = append(s.snapshot.ResetStreams, frame.Header().StreamID)
			s.mu.Unlock()
		case *http2.PingFrame:
			if !frame.Flags.Has(http2.FlagPingAck) {
				writeMu.Lock()
				err = framer.WritePing(true, frame.Data)
				writeMu.Unlock()
				if err != nil {
					return
				}
			}
		case *http2.GoAwayFrame:
			return
		}
	}
}
