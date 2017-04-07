package gopaccap

import (
	"testing"
)

// This is a test function for testing travis testing
func TestAverage(t *testing.T) {
	v := 1.5
	if v != 1.5 {
		t.Error("Expected 1.5, got ", v)
	}
}
