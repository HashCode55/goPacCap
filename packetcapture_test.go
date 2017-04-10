package gopaccap

import (
	"testing"
)

func TestReadPCAP(t *testing.T) {
	// test if gopaccap is able to read pcap files or not
	_, err := readPackets("tcp", "example/test0.pcap")
	if err != nil {
		t.Error("Couldn't read pcap files.")
	}
}

func TestReadPCAPerr(t *testing.T) {
	_, err := readPackets("tcp", "example/test.pcap")
	if err == nil {
		t.Error("Couldn't read pcap files.")
	}
}

func TestTCPPackets(t *testing.T) {
	// test detection of TCP packets
	pc := PacketCapture(5, false, "")
	// This will load the packet into the channel
	pkts, err := pc.ReadPcap("tcp", "example/test1.pcap")
	if err != nil {
		t.Error(err.Error())
	}
	l := len(pkts)
	if l != 6 {
		t.Errorf("pcap had 6 tcp packets, %d detected", l)
	}
}

func TestUDPPackets(t *testing.T) {
	pc := PacketCapture(5, false, "")
	pkts, err := pc.ReadPcap("udp", "example/test2.pcap")
	if err != nil {
		t.Error(err.Error())
	}
	l := len(pkts)
	if l != 66 {
		t.Errorf("pcap had 66 udp packets, %d detected", l)
	}
}

func TestICMPfail(t *testing.T) {
	// This is bound to fail as ICMP is not a
	// transport layer protocol
	pc := PacketCapture(5, false, "")
	_, err := pc.ReadPcap("icmp", "example/test3.pcap")
	if err == nil {
		t.Fail()
	}
}
