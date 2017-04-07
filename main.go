package main

import (
	"./paccap"
	"fmt"
)

func main() {
	fmt.Println("worked")
	paccap.LiveCapture("TCP", "et0")
}
