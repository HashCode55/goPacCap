package main

import (
	".."
	log "github.com/Sirupsen/logrus"
	"time"
)

var logger = log.New()

func main() {
	pc := gopaccap.PacketCapture(5)

	// run capture as a goroutine and yay!
	go pc.LiveCapture("tcp", "en0", 65535, false, -1*time.Second)

	// a simple select statement to receive the packets
	for {
		select {
		case p := <-pc.PackChan:
			logger.Infof("[PacCap ] %s", p)
		}
	}
}
