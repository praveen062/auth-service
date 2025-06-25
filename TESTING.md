# Testing Documentation

This document provides comprehensive information about the test suite for the auth-service project.

## Overview

The auth-service includes a comprehensive test suite covering all major components:

- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **Mock Tests**: Service layer testing with mocks
- **Configuration Tests**: Config loading and validation
- **Middleware Tests**: RBAC middleware functionality
- **Model Tests**: Data structure validation

## Test Structure

```
auth-service/
├── internal/
│   ├── config/
│   │   ├── config.go
│   │   └── config_test.go          # Configuration tests
│   ├── handler/
│   │   └── rest/
│   │       ├── auth_handler.go
│   │       ├── auth_handler_test.go    # Auth handler tests
│   │       ├── oauth_handler.go
│   │       └── oauth_handler_test.go   # OAuth handler tests
│   ├── middleware/
│   │   ├── rbac_middleware.go
│   │   └── rbac_middleware_test.go     # RBAC middleware tests
│   ├── models/
│   │   ├── role.go
│   │   └── role_test.go                # Model validation tests
│   └── service/
│       ├── rbac_service.go
│       └── rbac_service_test.go        # Service layer tests
├── cmd/
│   └── server/
│       ├── main.go
│       └── main_test.go                # Main application tests
├── test.sh                             # Test runner script
└── TESTING.md                          # This file
```

## Running Tests

### Quick Test Run

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...
```

### Using the Test Runner Script

The project includes a comprehensive test runner script that provides detailed reporting:

```bash
# Make the script executable (first time only)
chmod +x test.sh

# Run the complete test suite
./test.sh
```

The test runner script will:
- Run all tests with coverage
- Generate HTML coverage reports
- Run race condition detection
- Run static analysis tools
- Generate detailed test logs
- Provide a summary report

### Individual Test Suites

```bash
# Test configuration
go test -v ./internal/config/

# Test handlers
go test -v ./internal/handler/rest/

# Test middleware
go test -v ./internal/middleware/

# Test service layer
go test -v ./internal/service/

# Test models
go test -v ./internal/models/

# Test main application
go test -v ./cmd/server/
```

## Test Coverage

### Configuration Tests (`internal/config/config_test.go`)

Tests the configuration loading and validation:

- **LoadConfig_Success**: Tests successful config loading from file
- **LoadConfig_FileNotFound**: Tests error handling for missing config file
- **LoadConfig_InvalidYAML**: Tests error handling for invalid YAML
- **LoadConfig_WithEnvironmentVariables**: Tests environment variable overrides
- **LoadConfig_DefaultValues**: Tests default value assignment
- **DatabaseConfig_GetDSN**: Tests database connection string generation
- **RedisConfig_GetRedisAddr**: Tests Redis address generation
- **Config_Validation**: Tests configuration validation
- **Config_CompleteConfiguration**: Tests complete configuration loading

### Authentication Handler Tests (`internal/handler/rest/auth_handler_test.go`)

Tests the authentication endpoints:

- **Login_Success**: Tests successful user login
- **Login_InvalidEmail**: Tests login with invalid email
- **Login_MissingFields**: Tests login with missing required fields
- **Login_InvalidJSON**: Tests login with invalid JSON
- **Register_Success**: Tests successful user registration
- **Register_InvalidEmail**: Tests registration with invalid email
- **Register_MissingFields**: Tests registration with missing fields
- **Register_EmptyPassword**: Tests registration with empty password
- **RefreshToken_Success**: Tests successful token refresh
- **RefreshToken_MissingToken**: Tests refresh with missing token
- **Logout_Success**: Tests successful logout
- **NewAuthHandler**: Tests handler initialization

### OAuth Handler Tests (`internal/handler/rest/oauth_handler_test.go`)

Tests the OAuth endpoints:

- **GoogleLogin_Success**: Tests Google OAuth login initiation
- **GoogleLogin_WithCustomRedirectURI**: Tests custom redirect URI handling
- **GoogleLogin_MissingTenantID**: Tests missing tenant ID error
- **GoogleCallback_Success**: Tests Google OAuth callback
- **GoogleCallback_MissingCode**: Tests missing authorization code
- **GoogleCallback_OAuthError**: Tests OAuth error handling
- **ClientCredentials_Success**: Tests client credentials flow
- **ClientCredentials_UnsupportedGrantType**: Tests unsupported grant type
- **ClientCredentials_InvalidJSON**: Tests invalid JSON handling
- **CreateOneTimeToken_Success**: Tests one-time token creation
- **CreateOneTimeToken_MissingURL**: Tests missing URL error
- **VerifyOneTimeToken_Success**: Tests token verification
- **VerifyOneTimeToken_MissingToken**: Tests missing token error
- **VerifyOneTimeToken_InvalidToken**: Tests invalid token handling
- **RefreshSession_Success**: Tests session refresh
- **RefreshSession_MissingSessionID**: Tests missing session ID error
- **NewOAuthHandler**: Tests handler initialization

### RBAC Middleware Tests (`internal/middleware/rbac_middleware_test.go`)

Tests the role-based access control middleware:

- **UserHasPermission_Success**: Tests successful permission check
- **UserDoesNotHavePermission**: Tests denied permission
- **MissingUserID**: Tests missing user ID error
- **MissingTenantID**: Tests missing tenant ID error
- **RBACServiceError**: Tests service error handling
- **DifferentPermissions**: Tests various permission types
- **DifferentUsers**: Tests different user scenarios
- **DifferentTenants**: Tests multi-tenant scenarios

### Service Layer Tests (`internal/service/rbac_service_test.go`)

Tests the RBAC service interface with mocks:

- **AssignRoleToUser_Success/Error**: Tests user role assignment
- **AssignRoleToService_Success/Error**: Tests service role assignment
- **AssignPermissionToRole_Success/Error**: Tests permission assignment
- **UserHasPermission_Success/NoPermission/Error**: Tests user permission checks
- **ServiceHasPermission_Success/NoPermission/Error**: Tests service permission checks
- **GetUserRoles_Success/Error**: Tests user role retrieval
- **GetRolePermissions_Success/Error**: Tests role permission retrieval
- **Integration_UserRoleAssignment**: Tests complete user role flow
- **Integration_ServiceRoleAssignment**: Tests complete service role flow

### Model Tests (`internal/models/role_test.go`)

Tests the data model structures:

- **Role_Structure**: Tests role structure validation
- **Permission_Structure**: Tests permission structure validation
- **RolePermission_Structure**: Tests role-permission relationship
- **UserRole_Structure**: Tests user-role relationship
- **ServiceRole_Structure**: Tests service-role relationship
- **Validation Tests**: Tests field validation for all models
- **Special Characters**: Tests handling of special characters
- **Empty Fields**: Tests empty field handling

### Main Application Tests (`cmd/server/main_test.go`)

Tests the main application setup:

- **LoadConfig_Success/FileNotFound**: Tests configuration loading
- **IPAllowlistMiddleware**: Tests IP filtering middleware
- **ConfigurationValidation**: Tests configuration validation
- **DatabaseDSN_Generation**: Tests database connection string generation
- **RedisAddr_Generation**: Tests Redis address generation
- **EnvironmentVariableOverride**: Tests environment variable handling

## Test Utilities

### Mock Services

The test suite includes mock implementations for testing:

- **MockRBACService**: Mock implementation of the RBAC service interface
- **Test Configuration**: Helper functions for creating test configurations
- **Test Router Setup**: Helper functions for setting up test routers

### Test Helpers

```go
// Setup test router
func setupTestRouter() *gin.Engine

// Setup test configuration
func setupTestConfig() *config.Config

// Setup OAuth test configuration
func setupTestOAuthConfig() *config.Config
```

## Coverage Requirements

The project aims for **80% test coverage** across all packages. The test runner script will:

- Generate coverage reports in HTML format
- Display coverage percentages
- Warn if coverage falls below the threshold
- Provide detailed coverage analysis

## Best Practices

### Writing Tests

1. **Use descriptive test names**: Test names should clearly describe what is being tested
2. **Follow AAA pattern**: Arrange, Act, Assert
3. **Test both success and failure cases**: Ensure error handling is tested
4. **Use table-driven tests**: For testing multiple scenarios
5. **Mock external dependencies**: Use mocks for database, external APIs, etc.
6. **Test edge cases**: Include boundary conditions and edge cases

### Example Test Structure

```go
func TestFunctionName_Scenario_ExpectedResult(t *testing.T) {
    // Arrange - Setup test data and mocks
    mockService := new(MockService)
    mockService.On("Method", "arg").Return("result", nil)
    
    // Act - Execute the function being tested
    result, err := functionUnderTest(mockService)
    
    // Assert - Verify the results
    assert.NoError(t, err)
    assert.Equal(t, "expected", result)
    mockService.AssertExpectations(t)
}
```

## Continuous Integration

The test suite is designed to work with CI/CD pipelines:

- **Exit codes**: Tests return appropriate exit codes for CI
- **Coverage reports**: Generate coverage data for CI tools
- **Race detection**: Detect race conditions in CI
- **Static analysis**: Run code quality checks

## Troubleshooting

### Common Issues

1. **Import errors**: Ensure all dependencies are installed (`go mod tidy`)
2. **Test failures**: Check test logs in `test-results/` directory
3. **Coverage issues**: Review uncovered code in `coverage.html`
4. **Race conditions**: Check `test-results/race-detection.log`

### Debugging Tests

```bash
# Run specific test with verbose output
go test -v -run TestSpecificFunction ./path/to/package

# Run tests with race detection
go test -race ./...

# Run tests with coverage for specific package
go test -coverprofile=coverage.out ./internal/config/
go tool cover -html=coverage.out
```

## Performance Testing

The test suite includes benchmarks for performance-critical components:

```bash
# Run benchmarks
go test -bench=. -benchmem ./...

# Run specific benchmark
go test -bench=BenchmarkFunctionName ./path/to/package
```

## Security Testing

The test suite includes security-focused tests:

- **Input validation**: Tests for malicious input handling
- **Authentication**: Tests for authentication bypass attempts
- **Authorization**: Tests for authorization bypass attempts
- **Data sanitization**: Tests for proper data sanitization

## Contributing

When adding new features or modifying existing code:

1. **Write tests first**: Follow TDD principles
2. **Maintain coverage**: Ensure new code is adequately tested
3. **Update documentation**: Keep this document updated
4. **Run full test suite**: Use `./test.sh` before committing

## Resources

- [Go Testing Package](https://golang.org/pkg/testing/)
- [Testify Assertion Library](https://github.com/stretchr/testify)
- [Gin Testing](https://github.com/gin-gonic/gin#testing)
- [Go Coverage](https://blog.golang.org/cover) 