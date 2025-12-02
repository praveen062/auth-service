#!/bin/bash

# Test runner script for auth-service
# This script runs all tests with coverage and generates reports

set -e

echo "🧪 Running tests for auth-service..."
echo "======================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go first."
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
print_status "Go version: $GO_VERSION"

# Set required environment variables for testing
print_status "Setting up test environment variables..."
export DB_HOST="test-db-host"
export DB_PASSWORD="test-db-password"
export JWT_SECRET="test-jwt-secret"
export SERVER_PORT="8080"
export DATABASE_HOST="test-database-host"
export DB_PORT="5432"
export DB_NAME="test-auth-service"
export DB_USER="test-user"
export REDIS_HOST="test-redis-host"
export REDIS_PORT="6379"
export REDIS_PASSWORD="test-redis-password"
export GOOGLE_CLIENT_ID="test-google-client-id"
export GOOGLE_CLIENT_SECRET="test-google-client-secret"

print_status "Environment variables set for testing:"
print_status "  DB_HOST=$DB_HOST"
print_status "  DB_PASSWORD=$DB_PASSWORD"
print_status "  JWT_SECRET=$JWT_SECRET"
print_status "  SERVER_PORT=$SERVER_PORT"
print_status "  DATABASE_HOST=$DATABASE_HOST"

# Clean previous test artifacts
print_status "Cleaning previous test artifacts..."
rm -rf coverage.out coverage.html test-results/

# Create test results directory
mkdir -p test-results

# Run tests with coverage
print_status "Running tests with coverage..."
go test -v -coverprofile=coverage.out -covermode=atomic ./... 2>&1 | tee test-results/test-output.log

# Check if tests passed
if [ $? -eq 0 ]; then
    print_success "All tests passed!"
else
    print_error "Some tests failed. Check test-results/test-output.log for details."
    exit 1
fi

# Generate coverage report
print_status "Generating coverage report..."
go tool cover -html=coverage.out -o coverage.html

# Get coverage percentage
COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
print_status "Test coverage: ${COVERAGE}%"

# Check coverage threshold (set to 80%)
COVERAGE_THRESHOLD=80
if (( $(echo "$COVERAGE >= $COVERAGE_THRESHOLD" | bc -l) )); then
    print_success "Coverage threshold met (${COVERAGE}% >= ${COVERAGE_THRESHOLD}%)"
else
    print_warning "Coverage below threshold (${COVERAGE}% < ${COVERAGE_THRESHOLD}%)"
fi

# Run specific test suites
print_status "Running specific test suites..."

# Test config package
print_status "Testing config package..."
go test -v ./internal/config/ 2>&1 | tee test-results/config-tests.log

# Test handlers
print_status "Testing handlers..."
go test -v ./internal/handler/rest/ 2>&1 | tee test-results/handler-tests.log

# Test middleware
print_status "Testing middleware..."
go test -v ./internal/middleware/ 2>&1 | tee test-results/middleware-tests.log

# Test service
print_status "Testing service layer..."
go test -v ./internal/service/ 2>&1 | tee test-results/service-tests.log

# Test models
print_status "Testing models..."
go test -v ./internal/models/ 2>&1 | tee test-results/model-tests.log

# Test main application
print_status "Testing main application..."
go test -v ./cmd/server/ 2>&1 | tee test-results/main-tests.log

# Run benchmarks if available
print_status "Running benchmarks..."
go test -bench=. -benchmem ./... 2>&1 | tee test-results/benchmarks.log

# Run race detection
print_status "Running race detection..."
go test -race ./... 2>&1 | tee test-results/race-detection.log

# Check for race conditions
if grep -q "WARNING: DATA RACE" test-results/race-detection.log; then
    print_error "Race conditions detected!"
    exit 1
else
    print_success "No race conditions detected"
fi

# Run vet
print_status "Running go vet..."
go vet ./... 2>&1 | tee test-results/vet.log

# Run staticcheck if available
if command -v staticcheck &> /dev/null; then
    print_status "Running staticcheck..."
    staticcheck ./... 2>&1 | tee test-results/staticcheck.log
else
    print_warning "staticcheck not installed. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest"
fi

# Generate test summary
print_status "Generating test summary..."
{
    echo "Test Summary Report"
    echo "=================="
    echo "Date: $(date)"
    echo "Go Version: $GO_VERSION"
    echo "Coverage: ${COVERAGE}%"
    echo ""
    echo "Test Results:"
    echo "- Config tests: $(grep -c 'PASS' test-results/config-tests.log || echo '0') passed"
    echo "- Handler tests: $(grep -c 'PASS' test-results/handler-tests.log || echo '0') passed"
    echo "- Middleware tests: $(grep -c 'PASS' test-results/middleware-tests.log || echo '0') passed"
    echo "- Service tests: $(grep -c 'PASS' test-results/service-tests.log || echo '0') passed"
    echo "- Model tests: $(grep -c 'PASS' test-results/model-tests.log || echo '0') passed"
    echo "- Main tests: $(grep -c 'PASS' test-results/main-tests.log || echo '0') passed"
    echo ""
    echo "Files generated:"
    echo "- coverage.html: HTML coverage report"
    echo "- coverage.out: Coverage data file"
    echo "- test-results/: Detailed test logs"
} > test-results/summary.txt

# Display summary
echo ""
echo "📊 Test Summary"
echo "==============="
cat test-results/summary.txt

echo ""
print_success "Test run completed successfully!"
print_status "Coverage report: coverage.html"
print_status "Test logs: test-results/"
print_status "Summary: test-results/summary.txt"

# Optional: Open coverage report in browser
if command -v open &> /dev/null; then
    read -p "Open coverage report in browser? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        open coverage.html
    fi
elif command -v xdg-open &> /dev/null; then
    read -p "Open coverage report in browser? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        xdg-open coverage.html
    fi
fi

echo ""
print_status "Test execution completed!" 