package gopaccap

import (
	"testing"
	"time"
)

func TestCache(t *testing.T) {
	pc := PacketCapture(5, false, "")
	// dummy packet
	pkt := Packet{FromIP: "0.0.0.0", ToIP: "1.1.1.1", FromPort: "22", ToPort: "22"}
	// Populate the cache
	pc.IPCache.Set(pkt)
	_, found := pc.IPCache.Get("0.0.0.0")
	if !found {
		t.Error("IP not cached.")
	}
}

func TestCacheWithLoad(t *testing.T) {
	// testgob has 178.154.131.217 in cache
	pc := PacketCapture(5, true, "example/testload.gob")
	_, found := pc.IPCache.Get("178.154.131.217")
	if !found {
		t.Error("IP table not loaded.")
	}
}

func TestCacheExpiration(t *testing.T) {
	c, err := NewIPCache(time.Microsecond, 2*time.Microsecond, false, "")
	if err != nil {
		t.Error(err.Error())
	}
	// dummy packet
	pkt := Packet{FromIP: "0.0.0.0", ToIP: "1.1.1.1", FromPort: "22", ToPort: "22"}
	c.Set(pkt)
	time.Sleep(time.Microsecond)
	_, found := c.Get("0.0.0.0")
	if found {
		t.Error("Cache is not expiring the entries.")
	}
}

func TestUpdateCache(t *testing.T) {
	ps, _ := readPackets("tcp", "example/test0.pcap")
	// get just one packet
	packet, _ := ps.NextPacket()
	// create a new packet capture object
	pc := PacketCapture(5, false, "")
	pc.UpdateCache(packet)
	_, found := pc.IPCache.Get("172.31.150.187")
	if !found {
		t.Error("Cache update failed")
	}
}

func TestCacheRead(t *testing.T) {
	_, err := loadIPCache("example/testload.gob")
	if err != nil {
		t.Error(err.Error())
	}
}

func TestCacheReadFail(t *testing.T) {
	_, err := loadIPCache("example/testload1.gob")
	if err == nil {
		t.Error("Cache load not failing for incorrect input.")
	}
}

func TestCacheFlush(t *testing.T) {
	pc := PacketCapture(5, false, "")
	// dummy packet
	pkt := Packet{FromIP: "0.0.0.0", ToIP: "1.1.1.1", FromPort: "22", ToPort: "22"}
	// Populate the cache
	pc.IPCache.Set(pkt)
	pc.IPCache.FlushIPCache()
	_, found := pc.IPCache.Get("0.0.0.0")
	if found {
		t.Error("Cache not flushed.")
	}
}
