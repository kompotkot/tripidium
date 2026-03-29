# tripidium

**Important: WIP**

A lightweight REST API server template with authentication basic functionality built in Go.

![logo](img/logo.png)

## Quick Start

```bash
# Build the application:
go build -tags sqlite -o tripidium ./cmd/tripidium

# Prepare access token private key:
./tripidium token

# Set environment variables:
vim .env

# Run the server:
./tripidium server
```

The server will start and listen on the configured address and port (default: `localhost:8020`).

## Documentation

- [Auth](docs/definitions/AUTH.md)
- [Endpoints](docs/definitions/ENDPOINTS.md) of server
- [Requirements](docs/definitions/REQUIREMENTS.md) for project requirements, available environment variables, etc
- [Structure](docs/definitions/STRUCTURE.md) for project structure details
