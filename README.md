# Multi-Tenant OAuth Service

A comprehensive, production-ready OAuth 2.0 service built in Go with support for multi-tenancy, Google OAuth, one-time authentication, and both REST API and gRPC interfaces.

## Features

- **Multi-Tenant Architecture**: Isolated tenant spaces with separate configurations
- **OAuth 2.0 Support**: Full OAuth 2.0 flow implementation
- **Google OAuth Integration**: Seamless Google authentication
- **One-Time Authentication**: Secure one-time auth for specific URLs
- **Dual API Support**: Both REST API and gRPC interfaces
- **Caching Layer**: Redis-based caching for performance optimization
- **JWT Tokens**: Secure token-based authentication
- **Database Persistence**: PostgreSQL with GORM for data management
- **Configuration Management**: Environment-based configuration with Viper
- **Structured Logging**: Zap-based logging for observability

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   REST API      │    │   gRPC API      │    │   OAuth Flow    │
│   (Gin)         │    │   (gRPC)        │    │   (Google)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Service Layer │
                    │   (Business     │
                    │    Logic)       │
                    └─────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Cache Layer   │    │   Database      │    │   Config        │
│   (Redis)       │    │   (PostgreSQL)  │    │   (Viper)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Project Structure

```
auth-service/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── config/
│   │   └── config.go
│   ├── models/
│   │   ├── tenant.go
│   │   ├── user.go
│   │   ├── session.go
│   │   └── oauth.go
│   ├── repository/
│   │   ├── tenant_repository.go
│   │   ├── user_repository.go
│   │   └── session_repository.go
│   ├── service/
│   │   ├── auth_service.go
│   │   ├── oauth_service.go
│   │   ├── tenant_service.go
│   │   └── cache_service.go
│   ├── handler/
│   │   ├── rest/
│   │   │   ├── auth_handler.go
│   │   │   ├── oauth_handler.go
│   │   │   └── tenant_handler.go
│   │   └── grpc/
│   │       ├── auth_grpc.go
│   │       └── proto/
│   │           └── auth.proto
│   ├── middleware/
│   │   ├── auth_middleware.go
│   │   ├── cors_middleware.go
│   │   └── logging_middleware.go
│   └── utils/
│       ├── jwt_utils.go
│       ├── password_utils.go
│       └── validation_utils.go
├── pkg/
│   ├── oauth/
│   │   └── google.go
│   └── cache/
│       └── redis.go
├── migrations/
│   └── 001_initial_schema.sql
├── configs/
│   ├── config.yaml
│   └── config.prod.yaml
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── go.mod
├── go.sum
└── README.md
```

## Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 13+
- Redis 6+
- Docker (optional)

### Environment Setup

1. Copy the example configuration:
```bash
cp configs/config.yaml configs/config.local.yaml
```

2. Update the configuration with your settings:
```yaml
server:
  port: 8080
  grpc_port: 9090

database:
  host: localhost
  port: 5432
  name: auth_service
  user: postgres
  password: password

redis:
  host: localhost
  port: 6379
  password: ""

oauth:
  google:
    client_id: "your-google-client-id"
    client_secret: "your-google-client-secret"
    redirect_url: "http://localhost:8080/oauth/google/callback"

jwt:
  secret: "your-jwt-secret-key"
  expiration_hours: 24
```

### Running the Service

1. Install dependencies:
```bash
go mod tidy
```

2. Run migrations:
```bash
go run cmd/server/main.go migrate
```

3. Start the service:
```bash
go run cmd/server/main.go
```

### Docker Setup

```bash
docker-compose up -d
```

## API Endpoints

### REST API

#### Authentication
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/refresh` - Refresh token
- `POST /api/v1/auth/logout` - User logout

#### OAuth
- `GET /api/v1/oauth/google/login` - Initiate Google OAuth
- `GET /api/v1/oauth/google/callback` - Google OAuth callback
- `POST /api/v1/oauth/one-time` - Create one-time auth token

#### Tenants
- `POST /api/v1/tenants` - Create tenant
- `GET /api/v1/tenants/:id` - Get tenant
- `PUT /api/v1/tenants/:id` - Update tenant
- `DELETE /api/v1/tenants/:id` - Delete tenant

### gRPC API

The service also exposes gRPC endpoints for the same functionality. See `internal/handler/grpc/proto/auth.proto` for the complete API definition.

## Multi-Tenancy

The service supports multi-tenancy through:

1. **Tenant Isolation**: Each tenant has isolated data and configurations
2. **Tenant-Specific OAuth**: Different OAuth providers per tenant
3. **Tenant Routing**: Automatic tenant detection and routing
4. **Tenant Configuration**: Per-tenant settings and limits

## Security Features

- JWT-based authentication
- Password hashing with bcrypt
- Rate limiting
- CORS protection
- Input validation
- SQL injection prevention
- XSS protection

## Performance Optimizations

- Redis caching for frequently accessed data
- Database connection pooling
- Efficient JWT validation
- Optimized database queries
- Response compression

## Monitoring and Observability

- Structured logging with Zap
- Request/response logging
- Error tracking
- Performance metrics
- Health check endpoints

## Development

### Running Tests
```bash
go test ./...
```

### Code Generation (gRPC)
```bash
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       internal/handler/grpc/proto/auth.proto
```

### Linting
```bash
golangci-lint run
```

## License

MIT License 