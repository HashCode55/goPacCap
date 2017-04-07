// Package paccap provides as easy-to-use interface for capturing
// and analysing the packets.
package paccap

// TODO: Expose two functions - ReadPcap and LiveCapture
// TODO: implement cache for keeping src IP and destination port, expiring after 5 minutes

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"time"

	"github.com/google/gopacket"
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

/////////////////////////
//  Exposed Functions  //
/////////////////////////

// ReadPcap reads the pcap files from the specified path and
// logs the packet details.
func ReadPcap(filter, path string) {
	fmt.Println(banner)
	// TODO: Logging
	packetSource, err := readPackets(filter, path)
	if err != nil {
		log.Fatal(err)
	}
	for packet := range packetSource.Packets() {
		// DO something
		fmt.Println(packet)
	}
}

// LiveCapture attaches with the NIC specified and starts capturing
// the packets logging the packet details
func LiveCapture(filter, device string) {
	fmt.Println(banner)

	packetSource, err := getPackets(filter, device)
	if err != nil {
		log.Fatal(err)
	}

	for packet := range packetSource.Packets() {
		// DO something
		fmt.Println(packet)
	}
}

/////////////////////////
//   Helper Functions  //
/////////////////////////

// getPackets returns the PacketSource for analysing the packets.

func readPackets(filter, path string) (*gopacket.PacketSource, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, err
	}
	// set the BPF filter
	err = handle.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	return packetSource, nil
}

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
		return nil, err
	}
	packetSource := gopacket.NewPacketSource(
		handle,
		handle.LinkType(),
	)
	return packetSource, nil
}
