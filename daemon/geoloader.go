package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Ipv4LpmKey struct {
	Prefixlen uint32
	Ipv4      uint32
}

func startGeoLoader(objs *XdpFilterObjects, blockedCountries string) {
	if blockedCountries == "" {
		log.Println("No blocked countries specified. Skipping GeoLoader.")
		return
	}

	// Support both space and comma as separators (#29 fix)
	blockedCountries = strings.ReplaceAll(blockedCountries, ",", " ")
	countries := strings.Fields(blockedCountries) // Fields splits on any whitespace and ignores extras

	go func() {
		ticker := time.NewTicker(7 * 24 * time.Hour)
		defer ticker.Stop()

		// Run immediately on startup
		runGeoUpdate(objs, countries)

		for range ticker.C {
			runGeoUpdate(objs, countries)
		}
	}()
}

func runGeoUpdate(objs *XdpFilterObjects, countries []string) {
	log.Printf("Starting GeoIP list update for %d countries\n", len(countries))

	// Download zone files sequentially to avoid 503 Rate Limiting from ipdeny.com
	type result struct {
		country string
		lines   []string
		err     error
	}

	results := make(chan result, len(countries))

	go func() {
		for _, country := range countries {
			country = strings.TrimSpace(strings.ToLower(country))
			if country == "" {
				continue
			}

			var lines []string
			var err error
			// Retry up to 3 times for 503/502 errors
			for attempt := 1; attempt <= 3; attempt++ {
				lines, err = fetchCountryZone(country)
				if err == nil {
					break
				}
				if strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), "502") {
					time.Sleep(time.Duration(attempt) * 2 * time.Second)
					continue
				}
				break
			}

			results <- result{country: country, lines: lines, err: err}
			time.Sleep(1 * time.Second) // Be nice to the API
		}
		close(results)
	}()

	// Collect all CIDRs before writing to BPF map
	// (#28 fix — clear map before inserting fresh data)
	allEntries := make(map[Ipv4LpmKey]uint8)
	for r := range results {
		if r.err != nil {
			log.Printf("Failed to fetch %s: %v", r.country, r.err)
			continue
		}
		count := 0
		for _, line := range r.lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			if ipnet.IP.To4() == nil {
				continue // IPv6 not yet supported
			}
			prefixLen, _ := ipnet.Mask.Size()
			// IPs from net.ParseCIDR are in network byte order (big-endian).
			// iph->saddr in the kernel is also in network byte order.
			ipUint32 := binary.LittleEndian.Uint32(ipnet.IP.To4())
			key := Ipv4LpmKey{
				Prefixlen: uint32(prefixLen),
				Ipv4:      ipUint32,
			}
			allEntries[key] = 1
			count++
		}
		log.Printf("Parsed %d subnets for %s", count, r.country)
	}

	// Clear obsolete entries from the map before loading new ones
	// The LPM trie with BPF_F_NO_PREALLOC doesn't have a native "clear all" call,
	// so we iterate over the map and delete any key that is not in our fresh allEntries map.
	var iterKey Ipv4LpmKey
	var iterVal uint8
	iter := objs.GeoMap.Iterate()
	deletedCount := 0
	for iter.Next(&iterKey, &iterVal) {
		if _, exists := allEntries[iterKey]; !exists {
			if err := objs.GeoMap.Delete(iterKey); err == nil {
				deletedCount++
			}
		}
	}
	if deletedCount > 0 {
		log.Printf("Removed %d obsolete CIDR blocks from GeoIP map", deletedCount)
	}

	totalLoaded := 0
	blockedValue := uint8(1)
	for key, val := range allEntries {
		if err := objs.GeoMap.Put(key, val); err != nil {
			log.Printf("Warning: failed to insert CIDR into BPF map: %v", err)
		} else {
			totalLoaded++
		}
		_ = blockedValue
	}

	log.Printf("GeoIP update complete. Total subnets loaded: %d", totalLoaded)
}

func fetchCountryZone(country string) ([]string, error) {
	url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", country)

	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return readLines(resp.Body), nil
}

func readLines(reader io.Reader) []string {
	var lines []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}
