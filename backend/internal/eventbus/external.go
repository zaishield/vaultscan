// §22 deepening: external event-bus adapters. The in-process Bus
// owns local fan-out + the bus_events durability log; ExternalSink
// pushes the same events to NATS (or, via the same interface, Kafka /
// Pub/Sub / SQS) so cross-process consumers can subscribe.
//
// Wiring: cmd/api/main.go calls Bus.AttachExternal(adapter); every
// subsequent Publish fans out to in-process subscribers AND fires the
// adapter's Forward. The adapter is best-effort — failures don't
// block the local Publish. Reliable redelivery for adapter failures
// rides on bus_events (a separate worker can replay from there).
package eventbus

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// ExternalSink is the contract every adapter satisfies. Forward MUST
// be non-blocking enough that one slow consumer can't stall the
// publisher — adapters are expected to fan into an internal queue.
type ExternalSink interface {
	Name() string
	Forward(ctx context.Context, ev Event) error
	Close() error
}

// AttachExternal wires an adapter so every Publish also forwards to
// it. The adapter is called AFTER the bus_events row is committed
// and AFTER the in-process handlers have been kicked off — so an
// adapter failure can't roll back the durability guarantee.
func (b *Bus) AttachExternal(sink ExternalSink) {
	b.extMu.Lock()
	b.ext = append(b.ext, sink)
	b.extMu.Unlock()
}

// publishExternal is invoked at the tail of Publish. Defined here so
// the core eventbus.go doesn't grow a NATS dependency.
//
// Goroutine governance: each Forward runs in its own goroutine with a
// 5s deadline. The Bus tracks them via b.extWg so DrainExternal can
// block on shutdown until they all finish (or its own deadline trips).
func (b *Bus) publishExternal(ev Event) {
	b.extMu.RLock()
	sinks := append([]ExternalSink(nil), b.ext...)
	b.extMu.RUnlock()
	for _, s := range sinks {
		b.extWg.Add(1)
		go func(sink ExternalSink) {
			defer b.extWg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = sink.Forward(ctx, ev)
		}(s)
	}
}

// DrainExternal blocks until either every in-flight external publish
// goroutine has returned, or the deadline elapses. Caller is expected
// to invoke this from main's shutdown sequence after http.Server
// has stopped accepting new requests.
func (b *Bus) DrainExternal(deadline time.Duration) {
	done := make(chan struct{})
	go func() {
		b.extWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(deadline):
	}
}

// NATSAdapter publishes events to subject "vaultscan.<event-type>".
// Subscribers wire onto subjects via standard NATS wildcards
// (`vaultscan.scan.*`, `vaultscan.>`).
type NATSAdapter struct {
	conn   *nats.Conn
	prefix string
}

func NewNATSAdapter(url string, opts ...nats.Option) (*NATSAdapter, error) {
	if url == "" {
		return nil, errors.New("eventbus/nats: url required")
	}
	if len(opts) == 0 {
		opts = []nats.Option{
			nats.Name("vaultscan-api"),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(2 * time.Second),
			nats.Timeout(5 * time.Second),
			nats.PingInterval(20 * time.Second),
			nats.MaxPingsOutstanding(2),
		}
	}
	conn, err := nats.Connect(url, opts...)
	if err != nil {
		return nil, err
	}
	return &NATSAdapter{conn: conn, prefix: "vaultscan"}, nil
}

func (n *NATSAdapter) Name() string { return "nats" }

func (n *NATSAdapter) Forward(_ context.Context, ev Event) error {
	if n.conn == nil || !n.conn.IsConnected() {
		return errors.New("eventbus/nats: not connected")
	}
	subject := n.prefix + "." + ev.Type
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	return n.conn.Publish(subject, body)
}

func (n *NATSAdapter) Close() error {
	if n.conn != nil {
		// Drain so in-flight publishes complete before close.
		_ = n.conn.Drain()
	}
	return nil
}

// ---- MockSink for tests ---------------------------------------------------

// MockSink records every event the bus forwards. Tests use this to
// confirm "did this event reach the external bus?" without standing
// up a real NATS server.
type MockSink struct {
	mu       sync.Mutex
	received []Event
}

func NewMockSink() *MockSink { return &MockSink{} }
func (m *MockSink) Name() string { return "mock" }
func (m *MockSink) Forward(_ context.Context, ev Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.received = append(m.received, ev)
	return nil
}
func (m *MockSink) Close() error { return nil }
func (m *MockSink) Received() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.received))
	copy(out, m.received)
	return out
}
