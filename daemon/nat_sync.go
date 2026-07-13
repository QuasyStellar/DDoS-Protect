package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Match both TCP and UDP DNAT rules in nftables
	nftRegex = regexp.MustCompile(`(tcp|udp) dport\s+(\d+)\s+(?:counter\s+)?dnat to\s+([0-9\.]+)(?::(\d+))?`)
	// Match both TCP and UDP DNAT rules in iptables
	iptRegex = regexp.MustCompile(`-p (tcp|udp).*?--dport\s+(\d+).*?-j DNAT --to-destination\s+([0-9\.]+)(?::(\d+))?`)
)

func startNatSync(objs *XdpFilterObjects) {
	// If the user specified NAT_MAPPINGS in .env, use them exclusively
	natMappings := os.Getenv("NAT_MAPPINGS")
	if natMappings != "" {
		log.Println("Using static NAT_MAPPINGS from .env")
		applyStaticMappings(objs, natMappings)
		return
	}

	log.Println("NAT_MAPPINGS not found in .env, starting Universal Auto-Discovery (nftables/iptables)")
	go func() {
		runNatDiscoveryCycle(objs)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			runNatDiscoveryCycle(objs)
		}
	}()
}

func runNatDiscoveryCycle(objs *XdpFilterObjects) {
	activeKeys := make(map[XdpFilterNatKey]bool)
	discoverAndApplyNftables(objs, activeKeys)
	discoverAndApplyIptables(objs, activeKeys)

	// Delete stale keys from BPF map
	var iterKey XdpFilterNatKey
	var iterVal XdpFilterNatValue
	iter := objs.NatMap.Iterate()
	deletedCount := 0
	for iter.Next(&iterKey, &iterVal) {
		if !activeKeys[iterKey] {
			if err := objs.NatMap.Delete(iterKey); err == nil {
				deletedCount++
			}
		}
	}
	if deletedCount > 0 {
		log.Printf("Removed %d obsolete NAT mappings from eBPF map", deletedCount)
	}
}

func applyStaticMappings(objs *XdpFilterObjects, mappingsStr string) {
	// Format: PublicPort:InternalIP:InternalPort, ...
	for _, mapping := range strings.Split(mappingsStr, ",") {
		mapping = strings.TrimSpace(mapping)
		if mapping == "" {
			continue
		}

		parts := strings.Split(mapping, ":")
		if len(parts) == 3 {
			pubPort, _ := strconv.Atoi(parts[0])
			intIP := net.ParseIP(parts[1]).To4()
			intPort, _ := strconv.Atoi(parts[2])

			if intIP != nil {
				// Insert for both TCP and UDP
				for _, proto := range []uint16{6, 17} {
					key := XdpFilterNatKey{
						PublicIp:   0, // Wildcard IP
						PublicPort: htons(uint16(pubPort)),
						Protocol:   proto,
					}
					val := XdpFilterNatValue{
						InternalIp:   binary.LittleEndian.Uint32(intIP), // LittleEndian memory layout guarantees bytes stay in original network order
						InternalPort: htons(uint16(intPort)),
					}
					if err := objs.NatMap.Put(key, val); err != nil {
						log.Printf("Failed to insert static NAT mapping proto=%d: %v", proto, err)
					} else {
						log.Printf("Added Static NAT (proto=%d): *:%d -> %s:%d", proto, pubPort, intIP.String(), intPort)
					}
				}
			}
		}
	}
}

func discoverAndApplyNftables(objs *XdpFilterObjects, activeKeys map[XdpFilterNatKey]bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").Output()
	if err != nil {
		return // Silently fail if nft is not available or errors out
	}

	matches := nftRegex.FindAllStringSubmatch(string(out), -1)
	for _, match := range matches {
		applyDiscoveredNat(objs, activeKeys, match[1], match[2], match[3], match[4])
	}
}

func discoverAndApplyIptables(objs *XdpFilterObjects, activeKeys map[XdpFilterNatKey]bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iptables", "-t", "nat", "-S").Output()
	if err != nil {
		return // Silently fail if iptables is not available
	}

	matches := iptRegex.FindAllStringSubmatch(string(out), -1)
	for _, match := range matches {
		applyDiscoveredNat(objs, activeKeys, match[1], match[2], match[3], match[4])
	}
}

func applyDiscoveredNat(objs *XdpFilterObjects, activeKeys map[XdpFilterNatKey]bool, protoStr, pubPortStr, intIPStr, intPortStr string) {
	pubPort, _ := strconv.Atoi(pubPortStr)
	intIP := net.ParseIP(intIPStr).To4()
	intPort := pubPort // Default to same port if not specified
	if intPortStr != "" {
		intPort, _ = strconv.Atoi(intPortStr)
	}

	if intIP == nil {
		return
	}

	// Determine protocol number
	var proto uint16
	switch strings.ToLower(protoStr) {
	case "udp":
		proto = 17
	default:
		proto = 6 // TCP
	}

	key := XdpFilterNatKey{
		PublicIp:   0,
		PublicPort: htons(uint16(pubPort)),
		Protocol:   proto,
	}
	activeKeys[key] = true

	val := XdpFilterNatValue{
		InternalIp:   binary.LittleEndian.Uint32(intIP), // LittleEndian memory layout guarantees bytes stay in original network order
		InternalPort: htons(uint16(intPort)),
	}

	// Only put if it doesn't exist or is different (to save CPU cycles)
	var existingVal XdpFilterNatValue
	if err := objs.NatMap.Lookup(key, &existingVal); err != nil || existingVal != val {
		if err := objs.NatMap.Put(key, val); err != nil {
			log.Printf("Failed to insert NAT mapping proto=%s *:%d -> %s:%d: %v", protoStr, pubPort, intIPStr, intPort, err)
		} else {
			log.Printf("NAT sync (proto=%s): *:%d -> %s:%d", protoStr, pubPort, intIPStr, intPort)
		}
	}
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return binary.LittleEndian.Uint16(b)
}
