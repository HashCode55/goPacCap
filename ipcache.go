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
// defaultExpiration is the default time after which the cache entries expire.
// iptable is a map object which stores the entries of cache as key value pairs.
// And tickInterval is the actual time after which the entries are deleted.
type IPCache struct {
	defaultExpiration time.Duration         // Expiration time of the items
	iptable           map[string]portObject // stores the ip as key and port as value
	mu                sync.RWMutex          // Mutex to control the access
	tickInterval      time.Duration         // The purge time for the cache
}

/////////////////////////
//  Exposed Functions  //
/////////////////////////

// Set populates the cache with the supplied
// ip as key and port as value.
func (c *IPCache) Set(ip string, prt string) {
	// add the default expiration to the current time
	e := time.Now().Add(c.defaultExpiration).UnixNano()
	// thread safe setting of the map
	// while this is accessing it no other set calls can be made
	c.mu.Lock()
	c.iptable[ip] = portObject{
		port:       prt,
		expiration: e,
	}
	c.mu.Unlock()
}

// Gets returns the corresponding value (that is port)
// to the IP given as argument.
func (c *IPCache) Get(ip string) (string, bool) {
	c.mu.RLock()
	portobj, found := c.iptable[ip]
	if !found {
		c.mu.RUnlock()
		// the ip was not found
		return "", false
	}
	if time.Now().UnixNano() > portobj.expiration {
		c.mu.RUnlock()
		// the entry has expired
		return "", false
	}
	c.mu.RUnlock()
	// the entry was found
	return portobj.port, true
}

// GetIPTable returns the snapshot of the IPtable
// as a map object
func (c *IPCache) GetIPTable() map[string]portObject {
	c.mu.RLock()
	m := make(map[string]portObject, len(c.iptable))
	now := time.Now().UnixNano()
	for k, v := range c.iptable {
		if now > v.expiration {
			continue
		}
		m[k] = v
	}
	c.mu.RUnlock()
	return m
}

// FlushIPCache clears the iptable
func (c *IPCache) FlushIPCache() {
	c.mu.Lock()
	c.iptable = map[string]portObject{}
	c.mu.Unlock()
}

// InspectCache takes the IP address as string returns
// a bool value telling whether the value is still in the
// IP table or not.
func (c *IPCache) InspectCache(ip string) bool {
	_, found := c.iptable[ip]
	if found {
		return true
	}
	return false
}

// NewIPCache creates returns a new IPCache. It takes two values as
// arguments, defaultexpiration which is the expiration time for the
// cache entries and tickinterval is the purge time for the expired
// entries
func NewIPCache(defaultexpiration, tickinterval time.Duration) *IPCache {
	iptable := make(map[string]portObject)
	c := &IPCache{
		defaultExpiration: defaultexpiration,
		iptable:           iptable,
		tickInterval:      tickinterval,
	}
	runManager(c, tickinterval)
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

	c.mu.Lock()
	for k, v := range c.iptable {
		if now > v.expiration {
			delete(c.iptable, k)
		}
	}
	c.mu.Unlock()
}

func run(c *IPCache) {
	// Beauutyy!
	// it calls delete expired after this specific interval
	ticker := time.NewTicker(c.tickInterval)
	for {
		select {
		case <-ticker.C:
			c.deleteExpired()
		}
	}
}

func runManager(c *IPCache, ci time.Duration) {
	// run as a goroutine and this is where the mutex lock becomes of
	// utmost importance
	go run(c)
}
