// Package paccap provides an easy-to-use interface for capturing
// and inspecting the packets with a miniscule implementation of IPCache.
package gopaccap

import (
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

/////////////////////////
// Global Declarations //
/////////////////////////

var logger = log.New()

// Packet stores the details of packets storing information about source
// IP/Port and destination IP/Port
type Packet struct {
	// FromIP is the Source IP
	FromIP string
	// ToIP is the Destination IP
	ToIP string
	// FromPort is the Source Port
	FromPort string
	// ToPort is the Destination Port
	ToPort string
}

// Pretty printing the packet
func (p Packet) String() string {
	return fmt.Sprintf("From %s:%s, To %s:%s}", p.FromIP, p.ToIP, p.FromPort, p.ToPort)
}

// Paccap is the enclosing packet capture struct. It encapsulates a
// *IPCache object, and a packet channel which stores the
// incoming packets
type Paccap struct {
	IPCache  *IPCache // cache object
	PackChan chan Packet
}

/////////////////////////
//  Exposed Functions  //
/////////////////////////

// PacketCapture creates a new instance of the Paccap
// struct initialising the IPCache.
// It takes a two arguments, cache expiration time and
// a bool value specifying whether to log cache hits or not.
func PacketCapture(exptime int) *Paccap {
	// create a new IPCache with et as expiration time
	et := time.Duration(exptime)
	// tick interval after which the entries are deleted
	ti := time.Duration(exptime + 1)
	ipc := NewIPCache(et*time.Minute, ti*time.Minute)

	// create a new channel
	packchan := make(chan Packet)

	// new instance of Paccap
	pc := &Paccap{IPCache: ipc, PackChan: packchan}
	return pc
}

// ReadPcap reads the pcap files from the specified path and
// logs the packet details. It takes two arguments, a packet filter
// specified as BPF, and the path of the pcap files. As it recognizes the packets
// it keeps on pushing the packets into a channel shared with the host process that is the
// client.
func (pc *Paccap) ReadPcap(filter, path string) {
	logger.Infof("[PacCap ] Starting to read from pcap file...")
	packetSource, err := readPackets(filter, path)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range packetSource.Packets() {
		sip, dip, err := getIPAddresses(packet)
		// if not recognized, log
		if err != nil {
			log.Errorf("[paccap ] %s", err.Error())
		}
		spn, dpn, err := getPortAddresses(packet)
		// log if not recognized
		if err != nil {
			log.Errorf("[paccap ] %s", err.Error())
		}

		pkt := Packet{FromIP: sip, ToIP: dip, FromPort: spn, ToPort: dpn}
		pc.PackChan <- pkt

		// populating the cache
		pc.IPCache.Set(pkt)
	}
}

// LiveCapture attaches with the NIC specified and starts capturing
// the packets logging the packet details. It caches the source IP of the
// packets recieved with the given expiration time. Takes BPF(filter),
// the device name, snapshot length, promiscous (boolean) and timeout time as
// arguments. As it recognizes the packets it keeps on pushing the packets into
// a channel shared with the host process that is the client.
func (pc *Paccap) LiveCapture(filter, device string, snapshotlen int32,
	promiscuous bool, timeout time.Duration) {
	logger.Info("[PacCap ] Capturing NIC to read the packets...")
	packetSource, err := getPackets(filter, device, snapshotlen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range packetSource.Packets() {
		sip, dip, err := getIPAddresses(packet)
		if err != nil {
			log.Errorf("[paccap ] %s", err.Error())
		}
		spn, dpn, err := getPortAddresses(packet)
		if err != nil {
			log.Errorf("[paccap ] %s", err.Error())
		}

		pkt := Packet{FromIP: sip, ToIP: dip, FromPort: spn, ToPort: dpn}
		pc.PackChan <- pkt

		// populating the cache
		pc.IPCache.Set(pkt)
	}
}

/////////////////////////
//   Helper Functions  //
/////////////////////////

func readPackets(filter, path string) (*gopacket.PacketSource, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, err
	}
	// set the BPF filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal("Check the filter. Possibly there is a syntax error.")
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	return packetSource, nil
}

// getPackets returns the PacketSource for analysing the packets.
func getPackets(filter, device string, snapshotlen int32,
	promiscuous bool, timeout time.Duration) (*gopacket.PacketSource, error) {
	handle, err := pcap.OpenLive(
		device,
		snapshotlen,
		promiscuous,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	// set the filter to monitor HTTP traffic for now
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal("Check the filter. Possibly there is a syntax error.")
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	return packetSource, nil
}

// getIPAddresses returns the IP addresses of source and
// Destination
func getIPAddresses(packet gopacket.Packet) (string, string, error) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String(), nil
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String(), nil
	}
	// create a new error
	err := errors.New("Couldn't inspect Network layer.")
	return "", "", err
}

// getPortAddresses returns the Port addresses of source and
// Destination
func getPortAddresses(packet gopacket.Packet) (string, string, error) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.SrcPort.String(), tcp.DstPort.String(), nil
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return udp.SrcPort.String(), udp.DstPort.String(), nil
	}
	// create a new error
	err := errors.New("Couldn't inspect Transport layer.")
	return "", "", err
}
