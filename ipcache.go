package gopaccap

import (
	"sync"
	"time"
)

/////////////////////////
//      Structs        //
/////////////////////////

type portObject struct {
	port       string
	expiration int64
}

// IPCache is a simple cache implementation which has four struct variables.
// DefaultExpiration is the default time after which the cache entries expire.
// IPTable is a map object which stores the entries of cache as key value pairs.
// And TickInterval is the actual time after which the entries are deleted.
type IPCache struct {
	DefaultExpiration time.Duration         // Expiration time of the items
	IPTable           map[string]portObject // stores the ip as key and port as value
	Mu                sync.RWMutex          // Mutex to control the access
	TickInterval      time.Duration         // The purge time for the cache
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
	// add the default expiration to the current time
	e := time.Now().Add(c.DefaultExpiration).UnixNano()
	// thread safe setting of the map
	// while this is accessing it no other set calls can be made
	c.Mu.Lock()
	c.IPTable[packet.FromIP] = portObject{
		port:       packet.ToPort,
		expiration: e,
	}
	c.Mu.Unlock()
}

// Gets returns the corresponding value (that is port)
// to the IP given as argument.
func (c *IPCache) Get(ip string) (string, bool) {
	c.Mu.RLock()
	portobj, found := c.IPTable[ip]
	if !found {
		c.Mu.RUnlock()
		// the ip was not found
		return "", false
	}
	if time.Now().UnixNano() > portobj.expiration {
		c.Mu.RUnlock()
		// the entry has expired
		return "", false
	}
	c.Mu.RUnlock()
	// the entry was found
	return portobj.port, true
}

// GetIPTable returns the snapshot of the IPTable
// as a map object
func (c *IPCache) GetIPTable() map[string]portObject {
	c.Mu.RLock()
	m := make(map[string]portObject, len(c.IPTable))
	now := time.Now().UnixNano()
	for k, v := range c.IPTable {
		if now > v.expiration {
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
	c.IPTable = map[string]portObject{}
	c.Mu.Unlock()
}

// InspectCache takes the IP address as string returns
// a bool value telling whether the value is still in the
// IP table or not.
func (c *IPCache) InspectCache(ip string) bool {
	_, found := c.IPTable[ip]
	if found {
		return true
	}
	return false
}

// NewIPCache creates returns a new IPCache. It takes two values as
// arguments, Defaultexpiration which is the expiration time for the
// cache entries and Tickinterval is the purge time for the expired
// entries
func NewIPCache(Defaultexpiration, Tickinterval time.Duration) *IPCache {
	IPTable := make(map[string]portObject)
	c := &IPCache{
		DefaultExpiration: Defaultexpiration,
		IPTable:           IPTable,
		TickInterval:      Tickinterval,
	}
	runManager(c, Tickinterval)
	return c
}

/////////////////////////
//   Helper Functions  //
/////////////////////////

// Delete all expired items from the IPCache.
func (c *IPCache) deleteExpired() {
	// current time
	now := time.Now().UnixNano()
	// lock while deleting

	c.Mu.Lock()
	for k, v := range c.IPTable {
		if now > v.expiration {
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
	// utmost importance
	go run(c)
}
