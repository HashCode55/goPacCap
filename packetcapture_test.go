package gopaccap

import (
	"testing"
)

func TestReadPCAP(t *testing.T) {
	_, err := readPackets("tcp", "testdata/test1.pcap")
	if err != nil {
		t.Fail()
	}
}

func TestLiveGetPackets(t *testing.T) {
	_, err := getPackets("tcp", "en0")
	if err != nil {
		t.Fail()
	}
}
