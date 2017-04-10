package main

import (
	"bufio"
	log "github.com/Sirupsen/logrus"
	"github.com/hashcode55/gopaccap"
	"os"
	"os/signal"
	"strings"
	"time"
)

// PATH to read from - the cache
var logger = log.New()

func main() {
	reader := bufio.NewReader(os.Stdin)
	breakSel := false
	// Refer https://golang.org/pkg/os/signal/#Notify
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	pc := gopaccap.PacketCapture(5, false, "")

	// run capture as a goroutine and yay!
	go pc.LiveCapture("tcp", "en0", 65535, false, -1*time.Second)

	// a simple select statement to receive the packets
	for {
		select {
		case p := <-pc.PackChan:
			logger.Infof("[PacCap ] %s", p)
		case <-c:
			log.Infof("[PacCap] Exiting Capture. Do you want to save the cache in a file? (y/n)")
			breakSel = true
		}
		if breakSel {
			break
		}
	}

	// ask the user for saving the cache
	text, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal(err.Error())
	}
	if strings.Compare(text, "y\n") == 0 {
		err := pc.IPCache.SaveIPCache("testsave.gob")
		if err != nil {
			log.Fatal(err.Error())
		}
		log.Infof("[PacCap] Cache successfully stored on disc.")
	}
}
