package actuator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDatabaseHealthCheck(t *testing.T) {
	// This test would require a real database connection
	// For now, we'll test the function creation
	check := DatabaseHealthCheck(nil)
	assert.NotNil(t, check)
}

func TestRedisHealthCheck(t *testing.T) {
	check := RedisHealthCheck(nil)
	assert.NotNil(t, check)

	// Test that it returns nil (success)
	err := check()
	assert.NoError(t, err)
}

func TestDiskSpaceHealthCheck(t *testing.T) {
	check := DiskSpaceHealthCheck(1)
	assert.NotNil(t, check)

	// Test that it returns nil (success)
	err := check()
	assert.NoError(t, err)
}

func TestMemoryHealthCheck(t *testing.T) {
	// Test with high threshold (should pass)
	check := MemoryHealthCheck(100)
	assert.NotNil(t, check)

	err := check()
	assert.NoError(t, err)

	// Test with very low threshold (should fail)
	check = MemoryHealthCheck(0)
	assert.NotNil(t, check)

	err = check()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "memory usage too high")
}

func TestGoroutineHealthCheck(t *testing.T) {
	// Test with high threshold (should pass)
	check := GoroutineHealthCheck(10000)
	assert.NotNil(t, check)

	err := check()
	assert.NoError(t, err)

	// Test with very low threshold (should fail)
	check = GoroutineHealthCheck(0)
	assert.NotNil(t, check)

	err = check()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too many goroutines")
}

func TestCustomHealthCheck(t *testing.T) {
	called := false
	checkFunc := func() error {
		called = true
		return nil
	}

	check := CustomHealthCheck(checkFunc)
	assert.NotNil(t, check)

	err := check()
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestTimeoutHealthCheck(t *testing.T) {
	// Test successful check
	checkFunc := func() error {
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	check := TimeoutHealthCheck(CustomHealthCheck(checkFunc), 100*time.Millisecond)
	assert.NotNil(t, check)

	err := check()
	assert.NoError(t, err)

	// Test timeout
	checkFunc = func() error {
		time.Sleep(200 * time.Millisecond)
		return nil
	}

	check = TimeoutHealthCheck(CustomHealthCheck(checkFunc), 50*time.Millisecond)
	assert.NotNil(t, check)

	err = check()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health check timed out")
}

func TestTimeoutHealthCheckWithError(t *testing.T) {
	// Test check that returns error
	checkFunc := func() error {
		return assert.AnError
	}

	check := TimeoutHealthCheck(CustomHealthCheck(checkFunc), 100*time.Millisecond)
	assert.NotNil(t, check)

	err := check()
	assert.Error(t, err)
	assert.Equal(t, assert.AnError, err)
}
