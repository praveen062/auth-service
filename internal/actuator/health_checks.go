package actuator

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"
	"time"

	"github.com/heptiolabs/healthcheck"
)

// DatabaseHealthCheck creates a health check for database connectivity
func DatabaseHealthCheck(db *sql.DB) healthcheck.Check {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		return db.PingContext(ctx)
	}
}

// RedisHealthCheck creates a health check for Redis connectivity
func RedisHealthCheck(redisClient interface{}) healthcheck.Check {
	return func() error {
		// This is a placeholder - you would implement actual Redis ping
		// For now, return nil to indicate success
		return nil
	}
}

// DiskSpaceHealthCheck creates a health check for disk space
func DiskSpaceHealthCheck(minSpaceGB int64) healthcheck.Check {
	return func() error {
		// This is a placeholder - you would implement actual disk space check
		// For now, return nil to indicate success
		return nil
	}
}

// MemoryHealthCheck creates a health check for memory usage
func MemoryHealthCheck(maxMemoryPercent int) healthcheck.Check {
	return func() error {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		// Calculate memory usage percentage
		memoryUsagePercent := float64(m.Sys) / float64(1<<30) * 100 // Convert to GB

		if memoryUsagePercent > float64(maxMemoryPercent) {
			return fmt.Errorf("memory usage too high: %.2f%%", memoryUsagePercent)
		}

		return nil
	}
}

// GoroutineHealthCheck creates a health check for goroutine count
func GoroutineHealthCheck(maxGoroutines int) healthcheck.Check {
	return func() error {
		count := runtime.NumGoroutine()
		if count > maxGoroutines {
			return fmt.Errorf("too many goroutines: %d", count)
		}
		return nil
	}
}

// CustomHealthCheck creates a custom health check function
func CustomHealthCheck(checkFunc func() error) healthcheck.Check {
	return checkFunc
}

// TimeoutHealthCheck wraps a health check with a timeout
func TimeoutHealthCheck(check healthcheck.Check, timeout time.Duration) healthcheck.Check {
	return func() error {
		done := make(chan error, 1)
		go func() {
			done <- check()
		}()

		select {
		case err := <-done:
			return err
		case <-time.After(timeout):
			return fmt.Errorf("health check timed out after %v", timeout)
		}
	}
}
