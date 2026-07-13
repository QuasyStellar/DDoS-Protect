package main

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
)

// TestLoadXDPObjects verifies that the compiled eBPF ELF binary
// can be parsed and loaded into the kernel structures correctly.
// Note: This requires root privileges or CAP_BPF / CAP_SYS_ADMIN capabilities.
func TestLoadXDPObjects(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping BPF test: must be run as root to load BPF objects")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("Failed to remove memlock: %v", err)
	}

	// Use the spec-based load path to also exercise dynamic map sizing (#34 fix)
	spec, err := LoadXdpFilter()
	if err != nil {
		t.Fatalf("Failed to load XDP spec: %v", err)
	}

	// Verify map specs are non-nil before accessing them (#15 / #34 fix)
	if spec.Maps["rate_limit_map"] == nil {
		t.Fatal("rate_limit_map spec is nil")
	}
	if spec.Maps["ip_bloom_map"] == nil {
		t.Fatal("ip_bloom_map spec is nil")
	}

	// Test dynamic sizing path (as done in main.go)
	ram := getAvailableRAM()
	factor := float64(ram) / (2.0 * 1024 * 1024 * 1024)
	if factor < 0.25 {
		factor = 0.25
	}
	if factor > 10.0 {
		factor = 10.0
	}
	baseEntries := uint32(100000 * factor)
	if m := spec.Maps["rate_limit_map"]; m != nil {
		m.MaxEntries = baseEntries
	}
	if m := spec.Maps["ip_bloom_map"]; m != nil {
		m.MaxEntries = baseEntries * 10
	}

	var objs XdpFilterObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatalf("Failed to load XDP objects: %v", err)
	}
	t.Cleanup(func() { objs.Close() }) // #36 fix: use t.Cleanup instead of defer for extensibility

	// Verify ALL maps and the program are non-nil (#35 fix)
	if objs.XdpDdosFilter == nil {
		t.Fatal("XDP Program is nil after loading")
	}
	maps := map[string]interface{}{
		"StatsMap":         objs.StatsMap,
		"ConfigMap":        objs.ConfigMap,
		"RateLimitMap":     objs.RateLimitMap,
		"IpBloomMap":       objs.IpBloomMap,
		"GlobalUdpRateMap": objs.GlobalUdpRateMap,
		"PortUdpRateMap":   objs.PortUdpRateMap,
		"AllowedPortsMap":  objs.AllowedPortsMap,
		"GeoMap":           objs.GeoMap,
		"NatMap":           objs.NatMap,
		"SniMap":           objs.SniMap,
	}
	for name, m := range maps {
		if m == nil {
			t.Fatalf("Map %s is nil after loading", name)
		}
	}

	// Verify config map write works
	err = objs.ConfigMap.Put(uint32(0), XdpFilterConfigData{
		RateLimitPps: 100000,
		GlobalUdpPps: 100000,
	})
	if err != nil {
		t.Fatalf("Failed to write to config map: %v", err)
	}

	// Verify AllowedPortsMap write works
	if err := objs.AllowedPortsMap.Put(uint32(443), uint8(1)); err != nil {
		t.Fatalf("Failed to write to AllowedPortsMap: %v", err)
	}

	t.Logf("Successfully loaded XDP programs and all %d maps into kernel (RAM factor: %.2f, baseEntries: %d)",
		len(maps), factor, baseEntries)
}
