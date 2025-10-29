# Environment

Setting up the project environment.

Copy the environment file, configure and apply environment variables:

```bash
cp .env.sample dev.env
vim dev.env
source dev.env
```

## Variables

The application uses the following environment variables for configuration:

### Server Configuration

- `SERVER_ADDR` - Server address to bind to (default: `localhost`)
- `SERVER_PORT` - Server port to listen on (default: `8080`)
- `SERVER_CORS_WHITELIST` - Comma-separated list of allowed CORS origins (default: empty)
- `SERVER_CORS_ALLOWED_DEFAULT_METHODS` - Allowed HTTP methods for CORS requests (default: `GET, OPTIONS`)

### Database Configuration

- `DATABASE_TYPE` - Database type: `sqlite` or `psql` (default: `sqlite`)
- `DATABASE_URI` - Database connection string (default: `tripidium.sqlite` for sqlite, `postgres://postgres:postgres@localhost:5432/tripidium` for psql)
- `DATABASE_MAX_OPEN_CONNS` - Maximum number of open database connections (default: `10`)
- `DATABASE_CONN_MAX_LIFETIME_SEC` - Maximum lifetime of database connections in seconds (default: `30`)

### Logger Configuration

- `LOG_LEVEL` - Logging level (default: `info`)
- `LOG_FORMAT` - Logging format: `text` or `json` (default: `text`)
