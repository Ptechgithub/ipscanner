package engine

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/Ptechgithub/ipscanner/internal/iterator"
	"github.com/Ptechgithub/ipscanner/internal/ping"
	"github.com/Ptechgithub/ipscanner/internal/statute"
)

type Engine struct {
	generator  *iterator.IpGenerator
	ipQueue    *IPQueue
	ctx        context.Context
	cancelFunc context.CancelFunc
	ping       func(netip.Addr) (int, error)
	statute.Logger
}

func NewScannerEngine(opts *statute.ScannerOptions, ctx ...context.Context) *Engine {
	queue := NewIPQueue(opts)
	var contextToUse context.Context
	var cancel context.CancelFunc

	if len(ctx) > 0 {
		contextToUse = ctx[0]
	} else {
		contextToUse, cancel = context.WithCancel(context.Background())
	}

	p := ping.Ping{
		Options: opts,
	}

	return &Engine{
		ipQueue:    queue,
		ctx:        contextToUse,
		cancelFunc: cancel,
		ping:       p.DoPing,
		generator:  iterator.NewIterator(opts),
		Logger:     opts.Logger,
	}
}

func (e *Engine) GetAvailableIPs(desc bool) []netip.Addr {
	if e.ipQueue != nil {
		return e.ipQueue.AvailableIPs(desc)
	}
	return nil
}

func (e *Engine) Run() {
	for {
		select {
		case <-e.ctx.Done():
			e.Logger.Debug(" Scanner stopped: context cancelled.")
			return

		case <-e.ipQueue.available:
			e.Logger.Debug(" Starting new IP scan round...")
			
			if len(e.GetAvailableIPs(false)) >= 10 {
				e.Logger.Debug(" Reached 10 responsive IPs. Stopping scan.")
				e.cancelFunc()
				return
			}

			batch, err := e.generator.NextBatch()
			if err != nil {
				e.Logger.Error(" Failed to generate IP batch: %v", err)
				time.Sleep(2 * time.Second)
				continue
			}

			for _, ip := range batch {
				select {
				case <-e.ctx.Done():
					e.Logger.Debug("\033[32m Scan Completed.\033[0m")
					return
				default:
					e.Logger.Debug(" Pinging IP: %s", ip)

					if rtt, err := e.ping(ip); err == nil {
						ipInfo := statute.IPInfo{
							IP:        ip,
							Port:      statute.RandomWarpPort(), // <=== اصلاح شده
							RTT:       rtt,
							CreatedAt: time.Now(),
						}
						e.Logger.Debug(" Responsive IP: %s (RTT: %d ms)", ip, rtt)
						e.ipQueue.Enqueue(ipInfo)
					} else {
						if strings.Contains(err.Error(), ": i/o timeout") {
							e.Logger.Debug(" Timeout: No response from %s", ip)
						} else {
							e.Logger.Error(" Error pinging %s: %v", ip, err)
						}
					}
				}
			}

			e.Logger.Debug("")

		default:
			e.Logger.Debug(" Idle: running expiration check...")
			e.ipQueue.Expire()
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func (e *Engine) Cancel() {
	e.Logger.Debug(" Scan cancelled by user.")
	e.cancelFunc()
}