package nidhogg

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"golang.org/x/net/http2"
	"io"
	"net/http"

	nidhogg_api "github.com/aesleif/nidhogg/pkg/nidhogg"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Server is the inbound handler for the nidhogg protocol.
type Server struct {
	nidhoggServer *nidhogg_api.Server
	h2server      *http2.Server
}

// NewServer creates a nidhogg inbound handler from protobuf config.
func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	srv, err := nidhogg_api.NewServerEmbedded(nidhogg_api.ServerConfig{
		PSK:                        config.Psk,
		ProfileTargets:             config.ProfileTargets,
		TelemetryCriticalThreshold: int(config.TelemetryThreshold),
		ProfileMinSnapshots:        int(config.ProfileMinSnapshots),
	})
	if err != nil {
		return nil, errors.New("failed to create nidhogg server").Base(err)
	}

	// Start profile manager in background
	go srv.StartProfileManager(ctx)

	return &Server{
		nidhoggServer: srv,
		h2server:      &http2.Server{},
	}, nil
}

// Network implements proxy.Inbound.
func (s *Server) Network() []net.Network {
	return []net.Network{net.Network_TCP, net.Network_UDP}
}

// Process implements proxy.Inbound. Each call handles one HTTP/2 connection
// which may carry multiple multiplexed tunnel streams.
func (s *Server) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	inbound := session.InboundFromContext(ctx)
	if inbound != nil {
		inbound.Name = "nidhogg"
	}

	handler := s.tunnelHandler(ctx, dispatcher)

	s.h2server.ServeConn(conn, &http2.ServeConnOpts{
		Handler: handler,
	})

	return nil
}

// tunnelHandler returns an http.Handler that processes nidhogg tunnel streams.
func (s *Server) tunnelHandler(parentCtx context.Context, dispatcher routing.Dispatcher) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read and validate PSK handshake
		handshakeBuf := make([]byte, nidhogg_api.HandshakeSize())
		if _, err := io.ReadFull(r.Body, handshakeBuf); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		ok, err := s.nidhoggServer.ValidateHandshake(handshakeBuf)
		if !ok {
			errors.LogDebug(parentCtx, "nidhogg: handshake rejected: ", err)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Read binary destination header
		reader := bufio.NewReader(r.Body)
		d, err := nidhogg_api.ReadDest(reader)
		if err != nil {
			errors.LogWarning(parentCtx, "nidhogg: failed to read destination: ", err)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Handle telemetry
		if d.Command == nidhogg_api.CommandTelemetry {
			s.handleTelemetry(w, reader)
			return
		}

		// Parse destination for Xray dispatcher
		network := d.Network()
		destStr := d.Addr()
		dest, err := net.ParseDestination(network + ":" + destStr)
		if err != nil {
			errors.LogWarning(parentCtx, "nidhogg: invalid destination: ", destStr)
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Create session context for this stream
		parentInbound := session.InboundFromContext(parentCtx)
		streamCtx := session.ContextWithInbound(parentCtx, &session.Inbound{
			Source: parentInbound.Source,
			Tag:    parentInbound.Tag,
		})

		// Dispatch to Xray routing
		link, err := dispatcher.Dispatch(streamCtx, dest)
		if err != nil {
			errors.LogWarning(streamCtx, "nidhogg: dispatch failed for ", destStr, ": ", err)
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			return
		}

		// Start streaming response
		flusher, ok := w.(http.Flusher)
		if !ok {
			errors.LogError(streamCtx, "nidhogg: ResponseWriter does not support Flusher")
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Nidhogg-Tunnel", "1")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		// Send inline profile
		s.writeProfile(w, flusher)

		errors.LogInfo(streamCtx, "nidhogg tunnel opened to ", destStr, " (", network, ")")

		// Relay: request body → link.Writer, link.Reader → response
		streamCtx, cancel := context.WithCancel(streamCtx)
		defer cancel()

		var requestReader buf.Reader
		var responseWriter buf.Writer
		fw := &flushWriter{w: w, f: flusher}
		if network == "udp" {
			requestReader = &PacketReader{Reader: reader, Target: dest}
			responseWriter = &PacketWriter{Writer: fw, Target: dest}
		} else {
			requestReader = buf.NewReader(reader)
			responseWriter = buf.NewWriter(fw)
		}

		requestDone := func() error {
			return buf.Copy(requestReader, link.Writer)
		}

		responseDone := func() error {
			return buf.Copy(link.Reader, responseWriter)
		}

		if err := task.Run(streamCtx, task.OnSuccess(requestDone, task.Close(link.Writer)), responseDone); err != nil {
			common.Interrupt(link.Reader)
			common.Interrupt(link.Writer)
		}
	})
}

// writeProfile sends the current traffic profile inline.
func (s *Server) writeProfile(w http.ResponseWriter, flusher http.Flusher) {
	profJSON := s.nidhoggServer.CurrentProfileJSON()
	if profJSON != nil {
		var sizeBuf [4]byte
		binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(profJSON)))
		w.Write(sizeBuf[:])
		w.Write(profJSON)
	} else {
		w.Write([]byte{0, 0, 0, 0})
	}
	flusher.Flush()
}

// handleTelemetry processes a telemetry report from a client.
func (s *Server) handleTelemetry(w http.ResponseWriter, reader io.Reader) {
	var report nidhogg_api.TelemetryReport
	if err := json.NewDecoder(reader).Decode(&report); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	s.nidhoggServer.RecordTelemetry(report)

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Nidhogg-Tunnel", "1")
	w.WriteHeader(http.StatusOK)
	s.writeProfile(w, flusher)
}

// flushWriter wraps a ResponseWriter to flush after each write.
type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(b []byte) (int, error) {
	n, err := fw.w.Write(b)
	if fw.f != nil {
		fw.f.Flush()
	}
	return n, err
}

func init() {
	common.Must(common.RegisterConfig((*ServerConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*ServerConfig))
	}))
}
