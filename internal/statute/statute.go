package statute

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"
)

type TIPQueueChangeCallback func(ips []IPInfo)

type TDialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)
type TQuicDialerFunc func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error)
type THTTPClientFunc func(rawDialer TDialerFunc, tlsDialer TDialerFunc, quicDialer TQuicDialerFunc, targetAddr ...string) *http.Client

var HTTPPing = 1 << 1
var TLSPing = 1 << 2
var TCPPing = 1 << 3
var QUICPing = 1 << 4
var WARPPing = 1 << 5

type IPInfo struct {
	IP        netip.Addr
	Port      int
	RTT       int
	CreatedAt time.Time
}

type ScannerOptions struct {
	UseIPv4               bool
	UseIPv6               bool
	CidrList              []string // CIDR ranges to scan
	SelectedOps           int
	Logger                Logger
	InsecureSkipVerify    bool
	RawDialerFunc         TDialerFunc
	TLSDialerFunc         TDialerFunc
	QuicDialerFunc        TQuicDialerFunc
	HttpClientFunc        THTTPClientFunc
	UseHTTP3              bool
	UseHTTP2              bool
	DisableCompression    bool
	HTTPPath              string
	Referrer              string
	UserAgent             string
	Hostname              string
	WarpPrivateKey        string
	WarpPeerPublicKey     string
	WarpPresharedKey      string
	Port                  uint16
	IPQueueSize           int
	IPQueueTTL            time.Duration
	MaxDesirableRTT       int
	IPQueueChangeCallback TIPQueueChangeCallback
	ConnectionTimeout     time.Duration
	HandshakeTimeout      time.Duration
	TlsVersion            uint16
}

var warpPorts = []int{
	500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928,
	934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010,
	1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
	2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279,
	5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
}

func RandomWarpPort() int {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		return 2408
	}
	return warpPorts[int(b[0])%len(warpPorts)]
}