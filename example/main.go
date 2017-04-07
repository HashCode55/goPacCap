package main

// TODO: No absolute imports
import (
	"fmt"
	"github.com/hashcode55/gopaccap"
)

func main() {
	fmt.Println("worked")
	pc := gopaccap.PacketCapture()
	pc.LiveCapture("tcp", "en0")
}
