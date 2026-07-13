package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricRateLimitDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ddos_rate_limit_drops_total",
		Help: "Total number of packets dropped by the per-IP PPS rate limit",
	})
	metricUdpGlobalDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ddos_udp_global_drops_total",
		Help: "Total number of UDP packets dropped by the global/port limit",
	})
	metricGeoDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ddos_geo_drops_total",
		Help: "Total number of packets dropped by GeoIP blocking",
	})
	metricInvalidDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ddos_invalid_drops_total",
		Help: "Total number of packets dropped due to invalid headers (TCP/UDP/Fragments)",
	})
)

func startMetricsServer(objs *XdpFilterObjects) {
	metricsAddr := os.Getenv("METRICS_ADDR")
	if metricsAddr == "" {
		log.Println("METRICS_ADDR is not set. Prometheus metrics server is disabled.")
		return
	}

	// Start Prometheus HTTP server on a dedicated mux (no global state)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		server := &http.Server{
			Addr:         metricsAddr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  15 * time.Second,
		}

		log.Printf("Starting Prometheus metrics server on %s\n", metricsAddr)
		if err := server.ListenAndServe(); err != nil {
			log.Printf("Metrics server failed (non-fatal): %v", err)
		}
	}()

	// Polling loop to read BPF stats map
	go func() {
		// Use kernel's possible CPU count to correctly sum PERCPU_ARRAY values.
		// runtime.NumCPU() can be lower than possible CPUs in containerized environments.
		numCPUs := ebpf.MustPossibleCPU()
		prevStats := make(map[uint32]uint64)
		values := make([]uint64, numCPUs)

		for {
			time.Sleep(1 * time.Second)

			// Read stats map keys 0 to 4 (matches STAT_* defines in xdp_filter.c)
			for key := uint32(0); key <= 4; key++ {
				if err := objs.StatsMap.Lookup(key, &values); err == nil {
					var total uint64
					for i := 0; i < numCPUs && i < len(values); i++ {
						total += values[i]
					}

					// Calculate delta
					delta := total - prevStats[key]
					if delta > 0 {
						prevStats[key] = total
						// Map keys to metrics
						switch key {
						case 0: // STAT_GEO_DROP
							metricGeoDrops.Add(float64(delta))
						case 1: // STAT_RATE_LIMIT_DROP
							metricRateLimitDrops.Add(float64(delta))
						case 2, 3: // STAT_TCP_INVALID, STAT_UDP_INVALID
							metricInvalidDrops.Add(float64(delta))
						case 4: // STAT_GLOBAL_UDP_DROP
							metricUdpGlobalDrops.Add(float64(delta))
						}
					}
				}
			}
		}
	}()
}
