# OIDC-AUTH

A custom OpenID Connect style authentication server built with Node.js, Express, PostgreSQL, Drizzle ORM, JWT, and TypeScript.

This project is a backend-first identity service that can register users, authenticate credentials, issue RSA-signed JWTs, expose OIDC discovery metadata, publish a JWKS endpoint, and return user profile claims through a protected `userinfo` endpoint.

## What It Does

- User registration with salted SHA-256 password hashing
- User login with database-backed credential verification
- RSA private/public key based JWT signing and verification
- OIDC discovery endpoint at `/.well-known/openid-configuration`
- JWKS endpoint at `/.well-known/jwks.json`
- Protected user profile endpoint at `/o/userinfo`
- PostgreSQL persistence through Drizzle ORM
- Docker Compose setup for local PostgreSQL
- TypeScript build pipeline with strict compiler settings

## Tech Stack

| Layer | Technology |
| --- | --- |
| Runtime | Node.js |
| API | Express 5 |
| Language | TypeScript |
| Database | PostgreSQL |
| ORM | Drizzle ORM |
| Auth Tokens | JSON Web Tokens |
| Crypto | RSA keys, Node crypto, jose |
| Package Manager | pnpm |
| Local Infra | Docker Compose |

## Project Structure

```txt
OIDC-AUTH/
|-- cert/
|   |-- private-key.pem
|   `-- public-key.pub
|-- drizzle/
|   `-- 0000_open_shotgun.sql
|-- public/
|   `-- authenticate.html
|-- src/
|   |-- db/
|   |   |-- index.ts
|   |   `-- schema.ts
|   |-- utils/
|   |   |-- cert.ts
|   |   `-- user-token.ts
|   `-- index.ts
|-- docker-compose.yml
|-- drizzle.config.js
|-- key-gen.sh
|-- package.json
`-- tsconfig.json
```

## Getting Started

### 1. Install Dependencies

```bash
pnpm install
```

### 2. Start PostgreSQL

```bash
docker compose up -d
```

The included Compose file starts PostgreSQL with:

```txt
POSTGRES_USER=admin
POSTGRES_PASSWORD=admin
POSTGRES_DB=oidc_auth
PORT=5432
```

### 3. Create Environment File

Create a `.env` file in the `OIDC-AUTH` directory:

```env
DATABASE_URL=postgres://admin:admin@localhost:5432/oidc_auth
PORT=3000
```

### 4. Generate RSA Keys

JWTs are signed with the private key and verified with the public key.

```bash
bash key-gen.sh
```

This creates:

```txt
cert/private-key.pem
cert/public-key.pub
```

### 5. Run Database Migrations

```bash
pnpm db:migrate
```

Optional: open Drizzle Studio.

```bash
pnpm studio
```

### 6. Start the Server

Development mode:

```bash
pnpm dev
```

Production-style build:

```bash
pnpm build
pnpm start
```

Server runs on:

```txt
http://localhost:3000
```

## Available Scripts

| Command | Description |
| --- | --- |
| `pnpm dev` | Watches TypeScript files and restarts the built server |
| `pnpm build` | Compiles TypeScript into `dist/` |
| `pnpm start` | Runs the compiled server |
| `pnpm db:generate` | Generates Drizzle migrations from schema changes |
| `pnpm db:migrate` | Applies database migrations |
| `pnpm studio` | Opens Drizzle Studio |

## API Reference

### Health Check

```http
GET /health
```

Checks whether the API can reach PostgreSQL.

Success response:

```json
{
  "status": "ok",
  "db": "connected"
}
```

### OIDC Discovery

```http
GET /.well-known/openid-configuration
```

Returns public metadata used by OIDC clients.

Example response:

```json
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/o/authenticate",
  "userinfo_endpoint": "http://localhost:3000/o/userinfo",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json"
}
```

### JWKS

```http
GET /.well-known/jwks.json
```

Publishes the public signing key as JSON Web Key Set data so clients can verify issued JWTs.

### Authentication Page

```http
GET /o/authenticate
```

Serves the static authentication page from `public/authenticate.html`.

### Sign Up

```http
POST /o/authenticate/sign-up
Content-Type: application/json
```

Request body:

```json
{
  "firstName": "Rohan",
  "lastName": "Singh",
  "email": "rohan@example.com",
  "password": "strong-password"
}
```

Success response:

```json
{
  "status": "ok",
  "message": "user created successfully"
}
```

### Sign In

```http
POST /o/authenticate/sign-in
Content-Type: application/json
```

Request body:

```json
{
  "email": "rohan@example.com",
  "password": "strong-password"
}
```

Success response:

```json
{
  "success": true,
  "message": "Login successfull done",
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### User Info

```http
GET /o/userinfo
Authorization: Bearer <token>
```

Returns OIDC-style profile claims for the authenticated user.

Example response:

```json
{
  "sub": "user-uuid",
  "email": "rohan@example.com",
  "email_verified": false,
  "given_name": "Rohan",
  "family_name": "Singh",
  "name": "Rohan Singh",
  "picture": null
}
```

## Example cURL Flow

Register a user:

```bash
curl -X POST http://localhost:3000/o/authenticate/sign-up \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "Rohan",
    "lastName": "Singh",
    "email": "rohan@example.com",
    "password": "strong-password"
  }'
```

Log in:

```bash
curl -X POST http://localhost:3000/o/authenticate/sign-in \
  -H "Content-Type: application/json" \
  -d '{
    "email": "rohan@example.com",
    "password": "strong-password"
  }'
```

Fetch user info:

```bash
curl http://localhost:3000/o/userinfo \
  -H "Authorization: Bearer <paste-token-here>"
```

## Database Schema

The current `users` table stores:

| Column | Purpose |
| --- | --- |
| `id` | UUID primary key |
| `first_name` | User given name |
| `last_name` | User family name |
| `profile_image_url` | Optional profile image |
| `email` | Unique login identifier |
| `email_verified` | Email verification flag |
| `password` | Hashed password |
| `salt` | Per-user password salt |
| `created_at` | Creation timestamp |
| `updated_at` | Update timestamp |

## JWT Claims

Issued tokens include the core profile claims used by OIDC clients:

```json
{
  "iss": "http://localhost:3000",
  "sub": "user-uuid",
  "email": "rohan@example.com",
  "email_verified": "false",
  "exp": 1710000000,
  "given_name": "Rohan",
  "family_name": "Singh",
  "name": "Rohan Singh",
  "picture": ""
}
```

## Security Notes

This project is a strong foundation for learning and building a custom identity provider. Before using it in production, harden the following areas:

- Use `bcrypt`, `argon2`, or `scrypt` instead of plain salted SHA-256 for password storage.
- Add refresh tokens and token revocation if long-lived sessions are required.
- Add rate limiting for sign-up and sign-in endpoints.
- Validate request bodies with a schema library such as Zod.
- Store private keys securely outside the repository.
- Add HTTPS and configure the issuer from environment variables.
- Add key IDs (`kid`) to JWKS keys for smoother key rotation.
- Implement the complete authorization code flow if third-party OIDC clients need browser-based login.
- Add automated tests for authentication, token verification, and database behavior.

## Roadmap

- Authorization code flow
- Client registration
- Refresh token rotation
- Email verification
- Password reset
- Consent screen
- Admin client dashboard
- Dockerfile for API service deployment
- Automated integration test suite

## License

This project currently uses the ISC license from `package.json`.
