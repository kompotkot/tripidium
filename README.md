# tripidium

**Important: WIP**

A lightweight REST API server template with authentication basic functionality built in Go.

![logo](img/logo.png)

## Quick Start

Build the application:

```bash
go build -tags sqlite -o tripidium ./cmd/tripidium
```

Run the server:

```bash
./tripidium server
```

The server will start and listen on the configured address and port (default: `localhost:8080`).

## Documentation

- [Architecture](docs/definitions/ARCHITECTURE.md) for project structure details.
- [Endpoints](docs/definitions/ENDPOINTS.md) of server.
- [Requirements](docs/definitions/REQUIREMENTS.mdd) for project requirements, available environment variables ,etc.
