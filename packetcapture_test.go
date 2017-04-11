package gopaccap

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"testing"
)

func TestReadPCAP(t *testing.T) {
	// readPackets is an unexported function
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
	// Returns a packet array
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

func TestGetIPAddressFail(t *testing.T) {
	// Get an empty packet
	emptyPacket := getEmptyPacket()
	_, _, err := getIPAddresses(emptyPacket)
	if err == nil {
		t.Fail()
	}
}

func TestPortFail(t *testing.T) {
	// Get an empty packet
	emptyPacket := getEmptyPacket()
	_, _, err := getPortAddresses(emptyPacket)
	if err == nil {
		t.Fail()
	}
}

/////////////////////////
//  Helper Functions   //
/////////////////////////

func getEmptyPacket() gopacket.Packet {
	// Create an empty packet
	// Refer https://godoc.org/github.com/google/gopacket#hdr-Creating_Packet_Data
	payload := []byte{2, 4, 6}
	options := gopacket.SerializeOptions{}
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{},
		&layers.IPv4{},
		&layers.TCP{},
		gopacket.Payload(payload),
	)
	rawBytes := buffer.Bytes()

	// Decode an ethernet packet
	packet := gopacket.NewPacket(
		rawBytes,
		layers.LayerTypeEthernet,
		gopacket.Default,
	)
	return packet
}
