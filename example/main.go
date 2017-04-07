package main

// TODO: No absolute imports
import (
	".."
	"fmt"
)

func main() {
	fmt.Println("worked")
	gopaccap.LiveCapture("tcp", "en0")
}
