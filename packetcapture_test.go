package gopaccap

import (
	"github.com/patrickmn/go-cache"
	"strings"
	"testing"
)

func TestReadPCAP(t *testing.T) {
	_, err := readPackets("tcp", "testdata/test1.pcap")
	if err != nil {
		t.Errorf("Couldn't read pcap files.")
	}
}

func TestTCPPackets(t *testing.T) {
	pc := PacketCapture(5, false)
	s := pc.ReadPcap("tcp", "testdata/test1.pcap")
	l := len(s)
	if l != 6 {
		t.Errorf("pcap had 6 tcp packets, %d detected", l)
	}
	for _, ele := range s {
		if strings.Contains(ele, "nil") {
			t.Errorf("Inspection Failed for TCP packets.")
		}
	}
}

func TestUDPPackets(t *testing.T) {
	pc := PacketCapture(5, false)
	s := pc.ReadPcap("udp", "testdata/test2.pcap")
	l := len(s)
	if l != 66 {
		t.Errorf("pcap had 66 udp packets, %d detected", l)
	}
	for _, ele := range s {
		if strings.Contains(ele, "nil") {
			t.Errorf("Inspection Failed for UDP packets.")
		}
	}
}

func TestICMPfail(t *testing.T) {
	// This is bound to fail as ICMP is not a
	// transport layer protocol
	pc := PacketCapture(5, false)
	s := pc.ReadPcap("icmp", "testdata/test3.pcap")
	for _, ele := range s {
		if !strings.Contains(ele, "nil") {
			t.Fail()
		}
	}
}

func TestCache(t *testing.T) {
	ps, err := readPackets("tcp", "testdata/test1.pcap")
	pc := PacketCapture(5, false)
	if err != nil {
		t.Errorf("Couldn't read pcap files.")
	}
	// Populate the cache
	// 172.31.150.187, 23.23.145.232 and 54.254.224.187 should be
	// present in the cache
	for packet := range ps.Packets() {
		sip, _ := getIPAddresses(packet)
		_, dpn := getPortAddresses(packet)
		pc.ipcache.Set(sip, dpn, cache.DefaultExpiration)
	}
	_, found := pc.ipcache.Get("172.31.150.187")
	if !found {
		t.Errorf("IP not cached.")
	}
	_, found = pc.ipcache.Get("23.23.145.232")
	if !found {
		t.Errorf("IP not cached.")
	}
	_, found = pc.ipcache.Get("54.254.224.187")
	if !found {
		t.Errorf("IP not cached.")
	}
}
