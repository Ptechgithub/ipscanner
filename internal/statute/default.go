package statute

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"net"
	"net/http"
	"time"
)

var FinalOptions *ScannerOptions

func DefaultHTTPClientFunc(rawDialer TDialerFunc, tlsDialer TDialerFunc, quicDialer TQuicDialerFunc, targetAddr ...string) *http.Client {
	var defaultDialer TDialerFunc
	if rawDialer == nil {
		defaultDialer = DefaultDialerFunc
	} else {
		defaultDialer = rawDialer
	}
	var defaultTLSDialer TDialerFunc
	if rawDialer == nil {
		defaultTLSDialer = DefaultTLSDialerFunc
	} else {
		defaultTLSDialer = tlsDialer
	}
	var defaultQuicDialer TQuicDialerFunc
	if quicDialer == nil {
		defaultQuicDialer = DefaultQuicDialerFunc
	} else {
		defaultQuicDialer = quicDialer
	}

	var transport http.RoundTripper
	if FinalOptions.UseHTTP3 {
		transport = &http3.RoundTripper{
			DisableCompression: FinalOptions.DisableCompression,
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				dest := addr
				if len(targetAddr) > 0 {
					dest = targetAddr[0]
				}
				return defaultQuicDialer(ctx, dest, tlsCfg, cfg)
			},
		}
	} else {
		trans := &http.Transport{
			DialContext:         defaultDialer,
			DialTLSContext:      defaultTLSDialer,
			ForceAttemptHTTP2:   FinalOptions.UseHTTP2,
			DisableCompression:  FinalOptions.DisableCompression,
			MaxIdleConnsPerHost: -1,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: FinalOptions.InsecureSkipVerify,
				ServerName:         FinalOptions.Hostname,
			},
		}
		transport = trans
	}

	return &http.Client{
		Transport: transport,
		Timeout:   FinalOptions.ConnectionTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func DefaultDialerFunc(ctx context.Context, network, addr string) (net.Conn, error) {
	fmt.Println(addr)
	d := &net.Dialer{
		Timeout: FinalOptions.ConnectionTimeout, // Connection timeout
		// Add other custom settings as needed
	}
	return d.DialContext(ctx, network, addr)
}

func getServerName(address string) (string, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return "", err // handle the error properly in your real application
	}
	return host, nil
}

func defaultTLSConfig(addr string) *tls.Config {
	allowInsecure := false
	sni, err := getServerName(addr)
	if err != nil {
		allowInsecure = true
	}

	if FinalOptions.Hostname != "" {
		sni = FinalOptions.Hostname
	}

	alpnProtocols := []string{"http/1.1"}

	// Add protocols based on flags
	if FinalOptions.UseHTTP3 {
		alpnProtocols = []string{"http/1.1"} // ALPN token for HTTP/3
	}
	if FinalOptions.UseHTTP2 {
		alpnProtocols = []string{"h2", "http/1.1"} // ALPN token for HTTP/2
	}

	// Initiate a TLS handshake over the connection
	return &tls.Config{
		InsecureSkipVerify: allowInsecure || FinalOptions.InsecureSkipVerify,
		ServerName:         sni,
		MinVersion:         FinalOptions.TlsVersion,
		MaxVersion:         FinalOptions.TlsVersion,
		NextProtos:         alpnProtocols,
	}
}

// DefaultTLSDialerFunc is a custom TLS dialer function
func DefaultTLSDialerFunc(ctx context.Context, network, addr string) (net.Conn, error) {
	// Dial the raw connection using the default dialer
	rawConn, err := DefaultDialerFunc(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	// Ensure the raw connection is closed in case of an error after this point
	defer func() {
		if err != nil {
			_ = rawConn.Close()
		}
	}()

	// Prepare the TLS client connection
	tlsClientConn := tls.Client(rawConn, defaultTLSConfig(addr))

	// Perform the handshake with a timeout
	err = tlsClientConn.SetDeadline(time.Now().Add(FinalOptions.HandshakeTimeout))
	if err != nil {
		return nil, err
	}

	err = tlsClientConn.Handshake()
	if err != nil {
		return nil, err // rawConn will be closed by the deferred function
	}

	// Reset the deadline for future I/O operations
	err = tlsClientConn.SetDeadline(time.Time{})
	if err != nil {
		return nil, err
	}

	// Return the established TLS connection
	// Cancel the deferred closure of rawConn since everything succeeded
	err = nil
	return tlsClientConn, nil
}

func DefaultQuicDialerFunc(ctx context.Context, addr string, _ *tls.Config, _ *quic.Config) (quic.EarlyConnection, error) {
	quicConfig := &quic.Config{
		MaxIdleTimeout:       FinalOptions.ConnectionTimeout,
		HandshakeIdleTimeout: FinalOptions.HandshakeTimeout,
	}
	return quic.DialAddrEarly(ctx, addr, defaultTLSConfig(addr), quicConfig)
}

// default logger

type Logger interface {
	Debug(s string, v ...interface{})
	Error(s string, v ...interface{})
}

type DefaultLogger struct{}

func (l DefaultLogger) Debug(s string, v ...interface{}) {
	fmt.Printf(fmt.Sprintf("%s\r\n", s), v...)
}

func (l DefaultLogger) Error(s string, v ...interface{}) {
	fmt.Printf(fmt.Sprintf("%s\r\n", s), v...)
}

func DefaultIPQueueChangeCallback(ips []IPInfo) {
	fmt.Printf("📋 Queue changed: %d responsive IP(s)\n", len(ips))
	fmt.Println("───────────────────────🌐 Result ───────────────────────")
	for i, ip := range ips {
		ts := ip.CreatedAt.Format("2006-01-02 15:04:05")
		ipWithPort := fmt.Sprintf("%s:%d", ip.IP.String(), ip.Port)
		fmt.Printf("🔹 %2d) IP: %-21s | RTT: %4d ms | TS: %s\n", i+1, ipWithPort, ip.RTT, ts)
	}
	fmt.Println("────────────────────────────────────────────────────────")
}

var DefaultCFRanges = []string{
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"104.16.0.0/12",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"2400:cb00::/32",
	"2405:8100::/32",
	"2405:b500::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2c0f:f248::/32",
	"2a06:98c0::/29",
}
