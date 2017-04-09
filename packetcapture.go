// Package paccap provides an easy-to-use interface for capturing
// and inspecting the packets with a miniscule implementation of IPCache.
package gopaccap

import (
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
var banner string = `                                               
$$$$$$$\                      $$$$$$\                      
$$  __$$\                    $$  __$$\                     
$$ |  $$ |$$$$$$\   $$$$$$$\ $$ /  \__| $$$$$$\   $$$$$$\  
$$$$$$$  |\____$$\ $$  _____|$$ |       \____$$\ $$  __$$\ 
$$  ____/ $$$$$$$ |$$ /      $$ |       $$$$$$$ |$$ /  $$ |
$$ |     $$  __$$ |$$ |      $$ |  $$\ $$  __$$ |$$ |  $$ |
$$ |     \$$$$$$$ |\$$$$$$$\ \$$$$$$  |\$$$$$$$ |$$$$$$$  |
\__|      \_______| \_______| \______/  \_______|$$  ____/ 
                                                 $$ |      
                                                 $$ |      
                                                 \__|      
`

var (
	snapshot_len int32         = 65535
	promiscuous  bool          = false
	timeout      time.Duration = -1 * time.Second
)

var logger = log.New()

// Paccap is the enclosing packet capture struct. It encapsulates a
// *IPCache object, a flag for logging the cache and a boolean channel
// exiting the LiveCapture goroutine.
type Paccap struct {
	ipcache *IPCache // cache object
	lc      bool     // flag for caching the log. Ignored while reading pcap files.
	Exit    chan bool
}

/////////////////////////
//  Exposed Functions  //
/////////////////////////

// PacketCapture creates a new instance of the Paccap
// struct initialising the ipcache.
// It takes a two arguments, cache expiration time and
// a bool value specifying whether to log cache hits or not.
func PacketCapture(exptime int, logcache bool) *Paccap {
	// create a new ipcache with et as expiration time
	et := time.Duration(exptime)
	// tick interval after which the entries are deleted
	ti := time.Duration(exptime + 1)
	ipc := NewIPCache(et*time.Minute, ti*time.Minute)

	// make a channel to exit if Live capture launched
	// ignore if readpackets used
	ex := make(chan bool)
	// new instance of Paccap
	pc := &Paccap{ipcache: ipc, lc: logcache, Exit: ex}
	return pc
}

// ReadPcap reads the pcap files from the specified path and
// logs the packet details. It takes two arguments, a packet filter
// specified as BPF, and the path of the pcap files.
func (pc *Paccap) ReadPcap(filter, path string) []string {
	logger.Infof("[PacCap ] Starting to read from pcap file...")
	fmt.Println()
	packetSource, err := readPackets(filter, path)
	if err != nil {
		log.Fatal(err)
	}

	var packetdetails []string

	for packet := range packetSource.Packets() {
		sip, dip := getIPAddresses(packet)
		spn, dpn := getPortAddresses(packet)
		logger.Infof("[PacCap ] Packet Details -- SOURCE %v:%v | DESTINATION %v:%v",
			sip, spn, dip, dpn)

		s := fmt.Sprintf("src %s:%s | dst %s:%s", sip, spn, dip, dpn)
		packetdetails = append(packetdetails, s)
		fmt.Println()
	}
	return packetdetails
}

// LiveCapture attaches with the NIC specified and starts capturing
// the packets logging the packet details. It caches the source IP of the
// packets recieved with the given expiration time. Takes BPF(filter) and
// the device name as arguments.
func (pc *Paccap) LiveCapture(filter, device string) {
	fmt.Println(banner)
	logger.Info("[PacCap ] Capturing NIC to read the packets...")
	fmt.Println()
	packetSource, err := getPackets(filter, device)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range packetSource.Packets() {
		sip, dip := getIPAddresses(packet)
		spn, dpn := getPortAddresses(packet)
		logger.Infof("[PacCap ] Packet Captured! SOURCE %v:%v | DESTINATION %v:%v",
			sip, spn, dip, dpn)
		// observe cache hits
		_, found := pc.ipcache.Get(sip)
		if !found {
			pc.ipcache.Set(sip, dpn)
		} else if pc.lc {
			logger.Infof("[PacCap ] Cache hit! The above packet is already in cache.")
		}
		fmt.Println()
	}
}

// UpdateCache take a packet and updates the cache with the
// src IP and Destination Port. This way we can insert entries in the cache
// before starting a LiveCapture or after starting LiveCapture as a goroutine.
func (pc *Paccap) UpdateCache(packet gopacket.Packet) {
	sip, _ := getIPAddresses(packet)
	_, dpn := getPortAddresses(packet)
	// check if its already in cache
	_, found := pc.ipcache.Get(sip)
	if !found {
		pc.ipcache.Set(sip, dpn)
	} else if pc.lc {
		logger.Infof("[PacCap ] Failed to update cache. Key already in cache.")
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
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	return packetSource, nil
}

// getPackets returns the PacketSource for analysing the packets.
func getPackets(filter, device string) (*gopacket.PacketSource, error) {
	handle, err := pcap.OpenLive(
		device,
		snapshot_len,
		promiscuous,
		timeout,
	)
	if err != nil {
		return nil, err
	}
	// set the filter to monitor HTTP traffic for now
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	return packetSource, nil
}

// getIPAddresses returns the IP addresses of source and
// Destination
func getIPAddresses(packet gopacket.Packet) (string, string) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String()
	}
	log.Errorf("[PacCap ] Couldn't inspect Network Layer.")
	return "nil", "nil"
}

// getPortAddresses returns the Port addresses of source and
// Destination
func getPortAddresses(packet gopacket.Packet) (string, string) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.SrcPort.String(), tcp.DstPort.String()
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		return udp.SrcPort.String(), udp.DstPort.String()
	}
	log.Errorf("[PacCap ] Couldn't inspect Transport Layer.")
	return "nil", "nil"
}
