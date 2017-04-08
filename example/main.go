package main

import (
	"github.com/hashcode55/gopaccap"
)

func main() {
	pc := gopaccap.PacketCapture(5, false)
	pc.LiveCapture("tcp", "en0")
}
