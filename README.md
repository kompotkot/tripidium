# Tripidium

A lightweight template REST API server with authorization and basic functionality built in Go.

## Environment Variables

The application uses the following environment variables for configuration:

### Server Configuration

- `SERVER_ADDR` - Server address to bind to (default: `localhost`)
- `SERVER_PORT` - Server port to listen on (default: `8080`)
- `SERVER_CORS_WHITELIST` - Comma-separated list of allowed CORS origins (default: empty)
- `SERVER_CORS_ALLOWED_DEFAULT_METHODS` - Allowed HTTP methods for CORS (default: `GET, OPTIONS`)

### Database Configuration

- `DATABASE_URI` - PostgreSQL connection string
- `DATABASE_MAX_OPEN_CONNS` - Maximum number of open database connections (default: `10`)
- `DATABASE_CONN_MAX_LIFETIME_SEC` - Maximum lifetime of database connections in seconds (default: `30`)

### Logger Configuration

- `LOG_LEVEL` - Logging level (default: `info`)
- `LOG_FORMAT` - Logging format: `text` or `json` (default: `text`)

## Architecture

The project follows a clean architecture pattern with the following structure:

```
tripidium/
├── cmd/tripidium/        # Application entry point
│   └── main.go             # Main application file
├── internal/             # Private application code
│   ├── config/             # Configuration management
│   ├── logger/             # Structured logging
│   ├── server/             # HTTP server and handlers
│   └── types/              # Internal type definitions
├── pkg/                  # Public library code
│   ├── db/                 # Database connection and utilities
│   └── iam/                # Identity and access management
└── go.mod                # Go module definition
```

## Workflow

Copy environment file and configure variables

```bash
cp .env.sample dev.env
vim dev.env
source dev.env
```

Build the application

```bash
go build -o tripidium ./cmd/tripidium
```

Run the server

```bash
./tripidium
```

The server will start and listen on the configured address and port (default: `localhost:8080`).
