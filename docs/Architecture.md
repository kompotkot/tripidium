# Architecture

The project follows a clean architecture pattern with the following structure:

```
tripidium/
├── cmd/tripidium/        # Application entry point
│   └── main.go             # Main application file
├── internal/             # Private application code
│   ├── config/             # Configuration management
│   │   └── config.go
│   ├── logger/             # Structured logging
│   │   └── logger.go
│   ├── server/             # HTTP server and handlers
│   │   ├── handlers.go
│   │   ├── middlewares.go
│   │   └── server.go
│   └── types/              # Internal type definitions
│       └── types.go
├── pkg/                  # Public library code
│   ├── db/                # Database abstraction layer
│   │   ├── errors.go       # Database error definitions
│   │   ├── interface.go    # Database interface
│   │   ├── registry.go     # Database factory registry
│   │   ├── psql/           # PostgreSQL sub-module implementation (psql tag)
│   │   │   ├── factory.go
│   │   │   ├── go.mod
│   │   │   ├── go.sum
│   │   │   ├── init.go
│   │   │   ├── psql.go
│   │   │   └── README.md
│   │   └── sqlite/         # SQLite sub-module implementation (sqlite tag)
│   │       ├── factory.go
│   │       ├── go.mod
│   │       ├── go.sum
│   │       ├── init.go
│   │       ├── README.md
│   │       └── sqlite.go
│   └── iam/                # Identity and access management
│       └── users.go
├── docs/                  # Documentation
│   └── Architecture.md
├── go.mod                 # Go module definition
└── go.sum                 # Go module checksums
```
