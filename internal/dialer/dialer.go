package dialer

import (
	"context"
	"net"
	"time"
)

// TDialerFunc is a type definition for dialer functions.
type TDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// RawDialFunc is the raw dialer function.
var RawDialFunc TDialerFunc

// TLSDialFunc is the TLS dialer function.
var TLSDialFunc TDialerFunc

// DialerType represents the type of dialer.
type DialerType int

const (
	// RawDialer represents the non-TLS dialer type.
	RawDialer DialerType = iota
	// TLSDialer represents the TLS dialer type.
	TLSDialer
)

// CustomDialer is an interface for custom dialers.
type CustomDialer interface {
	// DialContext is used to establish a connection to a remote address.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Dial(network, address string) (net.Conn, error)
	// GetTimeout returns the timeout duration for the dialer.
	GetTimeout() time.Duration
	// SetTimeout sets the timeout duration for the dialer.
	SetTimeout(t time.Duration)
	// GetDialerType returns the type of the dialer.
	GetDialerType() DialerType
}

// appDialer is a common struct for AppDialer and AppTLSDialer.
type appDialer struct {
	Timeout    time.Duration
	DialerType DialerType
}

// GetTimeout returns the timeout duration for the dialer.
func (d *appDialer) GetTimeout() time.Duration {
	return d.Timeout
}

// SetTimeout sets the timeout duration for the dialer.
func (d *appDialer) SetTimeout(t time.Duration) {
	d.Timeout = t
}

// GetDialerType returns the type of the dialer.
func (d *appDialer) GetDialerType() DialerType {
	return d.DialerType
}

// DialContext implements the CustomDialer interface's Dial method.
func (d *appDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialFunc TDialerFunc

	if d.DialerType == RawDialer {
		dialFunc = RawDialFunc
	} else if d.DialerType == TLSDialer {
		dialFunc = TLSDialFunc
	}

	if dialFunc != nil {
		return dialFunc(ctx, network, address)
	}

	conn, err := net.DialTimeout(network, address, d.Timeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *appDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// AppDialer is a custom dialer for non-TLS connections.
type AppDialer struct {
	appDialer
}

func NewAppDialer(timeout time.Duration) *AppDialer {
	return &AppDialer{
		appDialer{
			Timeout:    timeout,
			DialerType: RawDialer,
		},
	}
}

// AppTLSDialer is a custom dialer for TLS connections.
type AppTLSDialer struct {
	appDialer
}

func NewAppTLSDialer(timeout time.Duration) *AppTLSDialer {
	return &AppTLSDialer{
		appDialer{
			Timeout:    timeout,
			DialerType: TLSDialer,
		},
	}
}
