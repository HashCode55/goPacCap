# goPacCap

Package paccap provides an easy-to-use interface for capturing
and inspecting the packets. Along comes with it is a very miniscule
implementation of IPCache.

## Getting Started 

To install the library 

```
go get github.com/hashcode55/gopaccap
```

### Dependencies 

```
go get github.com/google/gopacket
go get github.com/Sirupsen/logrus
```

### Usage

```
package main

import (
	log "github.com/Sirupsen/logrus"
	"github.com/hashcode55/gopaccap"
)

func main() {	
	// first argument is cache expiration time 
	// second is whetther to read cache from file or not 
	// third is the path from where to read 
	pc := gopaccap.PacketCapture(5, false, "")

	// run capture as a goroutine and yay!
	go pc.LiveCapture("tcp", "en0", 65535, false, -1*time.Second)

	// a simple select statement to receive the packets
	for {
		select {
		case p := <-pc.PackChan:
			log.Infof("[PacCap ] %s", p)
		case <-c:
			breakSel = true
		}
		if breakSel {
			break
		}
	}
	log.Info("Finished Capturing.")
}

```

<img src="images/gopaccap.gif">


## Running the tests


To run the tests, open the root of project and 

```
go test
```

## Documentation 

https://godoc.org/github.com/HashCode55/goPacCap

## Authors

* **Mehul Ahuja** 

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details
