// Package paccap provides as easy-to-use interface for capturing
// and analysing the packets.
package gopaccap

// TODO: Expose two functions - ReadPcap and LiveCapture
// TODO: implement cache for keeping src IP and destination port, expiring after 5 minutes

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/patrickmn/go-cache"
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

type paccap struct {
	ipcache *cache.Cache
}

/////////////////////////
//  Exposed Functions  //
/////////////////////////

// PacketCapture creates a new instance of the packet capturing
// device.
func PacketCapture() *paccap {
	// create a new cache with 5 minute expiration
	// and a purge time of 5 minutes
	ipc := cache.New(5*time.Minute, 5*time.Minute)
	// new instance of paccap
	pc := &paccap{ipcache: ipc}
	return pc
}

// ReadPcap reads the pcap files from the specified path and
// logs the packet details.
func (pc *paccap) ReadPcap(filter, path string) {
	fmt.Println(banner)
	logger.Infof("[PacCap ] Starting to read from pcap file...")
	fmt.Println()
	packetSource, err := readPackets(filter, path)
	if err != nil {
		log.Fatal(err)
	}
	for packet := range packetSource.Packets() {
		//TODO: Insert a delay for the streamlined info
		sip, dip := getIPAddresses(packet)
		spn, dpn := getPortAddresses(packet)
		logger.Infof("[PacCap ] Packet Captured! SOURCE %v:%v | DESTINATION %v:%v",
			sip, spn, dip, dpn)
		// adding src ip and destination to the cache
		pc.ipcache.Set(sip, dpn, cache.DefaultExpiration)
		fmt.Println()
	}
}

// LiveCapture attaches with the NIC specified and starts capturing
// the packets logging the packet details
func (pc *paccap) LiveCapture(filter, device string) {
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
		// _, found := pc.ipcache.Get(sip)
		// if found {
		// 	logger.Infof("[PacCap ] Cache hit!")
		// }
		pc.ipcache.Set(sip, dpn, cache.DefaultExpiration)
		fmt.Println()
	}
}

/////////////////////////
//   Helper Functions  //
/////////////////////////

// readPackets
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
		log.Fatal("Check the filter. Possibly there is a syntax error.")
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	return packetSource, nil
}

// GetIPAddresses returns the IP addresses of source and
// Destination
func getIPAddresses(packet gopacket.Packet) (string, string) {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip.SrcIP.String(), ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		return ip.SrcIP.String(), ip.DstIP.String()
	}
	log.Errorf("[PacCap ] Couldn't inspect IP payload.")
	return "nil", "nil"
}

// GetPortAddresses returns the Port addresses of source and
// Destination
func getPortAddresses(packet gopacket.Packet) (string, string) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		return tcp.SrcPort.String(), tcp.DstPort.String()
	}
	log.Errorf("[PacCap ] Couldn't inspect TCP payload.")
	return "nil", "nil"
}
