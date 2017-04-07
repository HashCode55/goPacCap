package main

// TODO: No absolute imports
import (
	"fmt"
	"github.com/hashcode55/gopaccap"
)

func main() {
	fmt.Println("worked")
	pc := gopaccap.PacketCapture()
	_ = pc.ReadPcap("tcp", "/Users/mehulahuja/Desktop/gopacketcap/testdata/test2.pcap")
}
