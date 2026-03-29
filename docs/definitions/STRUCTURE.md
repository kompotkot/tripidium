# Structure

The project follows a clean structure with the following tree:

```text
.
├── cmd                         # Executable entrypoints
│   └── tripidium               # Main application CLI
│       ├── imports_psql.go     # Registers PostgreSQL driver build
│       ├── imports_sqlite.go   # Registers SQLite driver build
│       └── main.go             # Application entry point and command handling
├── docker-compose.yml          # Local development services definition
├── Dockerfile                  # Container image build instructions
├── docs                        # Project documentation
│   ├── definitions             # Requirements, API, auth, and structure docs
│   │   ├── AUTH.md             # Authentication design and flows
│   │   ├── ENDPOINTS.md        # HTTP endpoint reference
│   │   ├── REQUIREMENTS.md     # Functional and configuration requirements
│   │   └── STRUCTURE.md        # Repository structure documentation
│   ├── diagrams                # Architecture and code diagrams
│   │   └── code
│   │       └── db-users.mermaid # User-related database diagram
│   └── README.md               # Documentation index
├── go.mod                      # Go module definition
├── go.sum                      # Go module checksums
├── img
│   └── logo.png                # Project logo
├── internal                    # Private application code
│   ├── config                  # Configuration management
│   │   └── config.go           # Env loading and config parsing
│   ├── logger                  # Structured logging
│   │   └── logger.go           # Logger setup and helpers
│   ├── server                  # HTTP server and handlers
│   │   ├── handlers.go         # Route handler implementations
│   │   ├── middlewares.go      # HTTP middleware chain
│   │   ├── responses.go        # Response DTOs and mapping helpers
│   │   └── server.go           # Router and server bootstrap
│   ├── service                 # Core business and auth logic
│   │   └── service.go          # Validation, password, and token services
│   └── types                   # Internal type definitions
│       └── types.go            # Shared config and application types
├── LICENSE                     # Project license
├── pkg                         # Reusable library code
│   ├── db                      # Database abstraction layer
│   │   ├── errors.go           # Database error definitions
│   │   ├── interface.go        # Database interface
│   │   ├── psql                # PostgreSQL implementation (psql tag)
│   │   │   ├── factory.go      # PostgreSQL factory registration
│   │   │   ├── go.mod          # Nested module for PostgreSQL driver deps
│   │   │   ├── go.sum
│   │   │   ├── init.go         # PostgreSQL package initialization
│   │   │   ├── psql.go         # PostgreSQL database implementation
│   │   │   └── README.md       # PostgreSQL package notes
│   │   ├── registry.go         # Database factory registry
│   │   └── sqlite              # SQLite implementation (sqlite tag)
│   │       ├── factory.go      # SQLite factory registration
│   │       ├── go.mod          # Nested module for SQLite driver deps
│   │       ├── go.sum
│   │       ├── init.go         # SQLite package initialization
│   │       ├── README.md       # SQLite package notes
│   │       └── sqlite.go       # SQLite database implementation
│   └── iam                     # Identity and access management models
│       └── iam.go              # User and auth-session domain types
└── README.md                   # Project overview and quick start
```
