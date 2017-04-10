package gopaccap

import (
	"encoding/gob"
	log "github.com/Sirupsen/logrus"
	"os"
	"sync"
	"time"
)

/////////////////////////
//      Structs        //
/////////////////////////

// PortObject is an encapsulation over the Port entries.
type PortObject struct {
	// Port is the destination Port which the cache will store.
	Port string
	// Expiration is the time after which the cache entry will be invalidated.
	Expiration int64
}

// IPCache is a simple cache implementation which has four struct variables.
// DefaultExpiration is the default time after which the cache entries expire.
// IPTable is a map object which stores the entries of cache as key value pairs.
// And TickInterval is the actual time after which the entries are deleted.
type IPCache struct {
	// DefaultExpiration is the Expiration time of the items
	DefaultExpiration time.Duration
	// IPTable stores the ip as key and Port as value
	IPTable map[string]PortObject
	// Mu is a mutex to control the access
	Mu sync.RWMutex
	// TickInterval is the purge time for the cache
	TickInterval time.Duration
}

/////////////////////////
//  Exposed Functions  //
/////////////////////////

// Set populates the cache with the supplied
// packet.
func (c *IPCache) Set(packet Packet) {
	// if the packet is already in the cache just return
	_, found := c.Get(packet.FromIP)
	if found {
		return
	}
	// add the default Expiration to the current time
	e := time.Now().Add(c.DefaultExpiration).UnixNano()
	// thread safe setting of the map
	// while this is accessing it no other set calls can be made
	c.Mu.Lock()
	c.IPTable[packet.FromIP] = PortObject{
		Port:       packet.ToPort,
		Expiration: e,
	}
	c.Mu.Unlock()
}

// Gets returns the corresponding value (that is Port)
// to the IP given as argument.
func (c *IPCache) Get(ip string) (string, bool) {
	c.Mu.RLock()
	Portobj, found := c.IPTable[ip]
	if !found {
		c.Mu.RUnlock()
		// the ip was not found
		return "", false
	}
	if time.Now().UnixNano() > Portobj.Expiration {
		c.Mu.RUnlock()
		// the entry has expired
		return "", false
	}
	c.Mu.RUnlock()
	// the entry was found
	return Portobj.Port, true
}

// GetIPTable returns the snapshot of the IPTable
// as a map object
func (c *IPCache) GetIPTable() map[string]PortObject {
	c.Mu.RLock()
	m := make(map[string]PortObject, len(c.IPTable))
	now := time.Now().UnixNano()
	for k, v := range c.IPTable {
		if now > v.Expiration {
			continue
		}
		m[k] = v
	}
	c.Mu.RUnlock()
	return m
}

// FlushIPCache clears the IPTable
func (c *IPCache) FlushIPCache() {
	c.Mu.Lock()
	c.IPTable = map[string]PortObject{}
	c.Mu.Unlock()
}

// InspectCache takes the IP address as string returns
// a bool value telling whether the value is still in the
// IP table or not. This is for testing.
func (c *IPCache) InspectCache(ip string) bool {
	_, found := c.IPTable[ip]
	if found {
		return true
	}
	return false
}

// SaveIPCache saves the IPTable in a file
func (c *IPCache) SaveIPCache(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := gob.NewEncoder(f)
	if err := enc.Encode(c.IPTable); err != nil {
		return err
	}
	return nil
}

// NewIPCache creates returns a new IPCache. It takes four values as
// arguments, DefaultExpiration which is the Expiration time for the
// cache entries, Tickinterval is the purge time for the expired
// entries, reacFromCache is a boolean variable which flags whether to read from
// file or not and finally the path to read from.
func NewIPCache(DefaultExpiration, Tickinterval time.Duration,
	readCache bool, path string) *IPCache {

	var IPTable map[string]PortObject
	if readCache {
		IPTable = loadIPCache(path)
	} else {
		IPTable = make(map[string]PortObject)
	}
	c := &IPCache{
		DefaultExpiration: DefaultExpiration,
		IPTable:           IPTable,
		TickInterval:      Tickinterval,
	}
	runManager(c, Tickinterval)
	return c
}

/////////////////////////
//   Helper Functions  //
/////////////////////////

func loadIPCache(path string) (iptable map[string]PortObject) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal("Can't open file.")
	}
	defer f.Close()
	enc := gob.NewDecoder(f)
	if err := enc.Decode(&iptable); err != nil {
		log.Fatal("Can't decode")
	}
	log.Info("Cache successfully loaded.")
	return iptable
}

// Delete all expired items from the IPCache.
func (c *IPCache) deleteExpired() {
	// current time
	now := time.Now().UnixNano()
	// lock while deleting

	c.Mu.Lock()
	for k, v := range c.IPTable {
		if now > v.Expiration {
			delete(c.IPTable, k)
		}
	}
	c.Mu.Unlock()
}

func run(c *IPCache) {
	// Beauutyy!
	// it calls delete expired after this specific interval
	ticker := time.NewTicker(c.TickInterval)
	for {
		select {
		case <-ticker.C:
			c.deleteExpired()
		}
	}
}

func runManager(c *IPCache, ci time.Duration) {
	// run as a goroutine and this is where the Mutex lock becomes of
	// utmost imPortance
	go run(c)
}
