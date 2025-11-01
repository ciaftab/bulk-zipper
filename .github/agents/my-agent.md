---
name: Aegis Folio
description: A security-first, headless backend system designed to safeguard and serve a personal portfolio. It provides a hardened admin panel with two-factor authentication and serves content via a secure, read-only public API, acting as a digital guardian for your professional work.
---

# My Agent

# Backend System Architecture: Admin-Controlled Portfolio with Public API

## Purpose

A secure backend system providing admin-controlled content management for portfolio components (blogs, projects, skills, experiences, education) with public read access and a hardened contact form. Designed for a single administrator with Google OAuth and email-based two-factor authentication. All public APIs are read-only; admin authentication required for content modifications.

---

## System Components

### Core Stack
- **Runtime:** Node.js LTS (v20.x)
- **Framework:** Express.js
- **Database:** MongoDB with replica set
- **Cache/Session Store:** Redis 7+
- **Language:** JavaScript (ES2022+)
- **Package Manager:** npm with package-lock.json

### Third-Party Services
- **Authentication:** Google OAuth 2.0 (OpenID Connect)
- **Email Delivery:** Brevo API (primary and secondary for redundancy)
- **Anti-Bot Protection:** Google reCAPTCHA v3
- **File Storage:** Cloudinary (authenticated delivery mode)
- **Malware Scanning:** VirusTotal API (private scanning mode)
- **Secrets Management:** AWS Secrets Manager or HashiCorp Vault

### Infrastructure Requirements
- HTTPS-only deployment with TLS 1.2+ (TLS 1.3 preferred)
- Private VPC with isolated database and Redis subnets
- NTP-synchronized servers (clock skew tolerance ≤ 30 seconds)
- Load balancer with health check support
- Centralized logging platform with encryption at rest

---

## Data Flow

### Public Content Access
1. Client requests public API endpoint (GET /api/blogs, /api/projects, etc.)
2. Rate limiting middleware validates request (1000 requests/hour/IP)
3. Query validation and sanitization
4. MongoDB query with projection for public fields only (isPublic=true)
5. Response with pagination metadata and cache headers
6. Static content served with ETag/Last-Modified for client caching

### Admin Authentication Flow
1. Admin initiates login at /admin/login (CSRF token cookie set)
2. OAuth redirect to Google with PKCE (S256), state, and nonce
3. Google callback with authorization code
4. Token exchange and OIDC token verification (signature, claims, timing)
5. Email canonicalization and comparison to ADMIN_GOOGLE_EMAIL
6. Pre-authentication session created (15-minute TTL)
7. OTP (8-digit) generated, hashed with Argon2id, sent to ADMIN_OTP_EMAIL
8. Admin submits OTP with CSRF protection
9. OTP verification with rate limiting and lockout protection
10. Full admin session created (4-hour absolute, 60-minute idle TTL)
11. Single active session enforcement (previous session invalidated)
12. Redirect to /admin/dashboard

### Contact Form Submission Flow
1. User completes form on /contact page (CSRF token set on page load)
2. Client-side reCAPTCHA v3 challenge (score threshold ≥ 0.7)
3. Form submission to POST /api/contact with multipart data
4. Server validates CSRF token, rate limit (5/hour/IP), honeypot, minimum time (5s)
5. Optional PDF attachment validated (MIME, extension, magic bytes, size ≤ 8MB)
6. File streamed to memory buffer, SHA-256 hash computed
7. Contact record created with status=pending_scan or new
8. Background job enqueued for virus scanning
9. Immediate generic success response to client
10. Worker checks SHA-256 against cache and VirusTotal (private mode)
11. Clean files uploaded to Cloudinary (authenticated, 30-day retention)
12. Admin notified of new contact with metadata summary
13. Admin accesses attachments via short-lived signed URLs (5-minute expiry)

### Admin Content Management Flow
1. Admin session validated (fresh, not expired, IP/UA match)
2. CSRF token validated on all state-changing operations
3. Request payload validated against strict schema
4. For updates/deletes: verify resource ownership and referential integrity
5. Cloud assets (Cloudinary) deleted before database records
6. Audit log entry created (immutable, timestamped, includes admin ID and IP)
7. Database transaction committed
8. Cache invalidation for affected public endpoints
9. Success response with updated resource or 204 No Content

---

## Security Architecture

### Transport and Network Security
- **HTTPS Enforcement:** Automatic HTTP to HTTPS redirect at load balancer
- **TLS Configuration:**
  - TLS 1.3 preferred, TLS 1.2 minimum (TLS 1.0/1.1 disabled)
  - Cipher suites: ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256
  - Perfect forward secrecy required
  - OCSP stapling enabled
  - Certificate rotation annually via automated process
- **Database Security:**
  - MongoDB: TLS 1.2+, SCRAM-SHA-256 authentication, connection pool (min=10, max=100)
  - Connection timeout: 10s, socket timeout: 30s
- **Redis Security:**
  - TLS encryption for all connections
  - Redis AUTH with 256-bit random password
  - ACL configuration restricting commands (disable FLUSHDB, FLUSHALL, CONFIG)
  - Network isolation in private subnet (no internet access)
  - Memory limit: 4GB with noeviction policy

### HTTP Security Headers
- **HSTS:** `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- **CSP:** `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self' 'nonce-<random>' https://www.google.com https://www.gstatic.com; connect-src 'self' https://www.google.com; img-src 'self' https://www.gstatic.com data:; frame-src https://www.google.com; base-uri 'self'; report-uri /api/csp-report`
- **Other Headers:**
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Cache-Control: no-store` (auth endpoints), `public, max-age=3600` (public GET with ETag)
  - `X-Frame-Options: DENY`

### Cookie Security
- **Session Cookie:** `__Host-admin_session`
  - HttpOnly, Secure, SameSite=Strict, Path=/
  - Expiry: 4 hours absolute from creation
- **Pre-Auth Cookie:** `__Host-pre_auth`
  - HttpOnly, Secure, SameSite=Strict, Path=/
  - Expiry: 15 minutes
- **CSRF Cookie:** `XSRF-TOKEN`
  - Secure, SameSite=Strict, Path=/
  - Not HttpOnly (readable by client for header mirroring)
  - Rotation: on login and every 15 minutes

### CSRF Protection
- Double-submit pattern: cookie + header validation
- Required on all state-changing endpoints
- Per-request tokens for critical operations (delete, publish, financial actions)
- Origin and Referer header validation as secondary check
- Token invalidation on logout

### Authentication Security

#### Google OAuth (OIDC)
- Authorization Code flow with PKCE (S256)
- State: 128-bit cryptographically random, one-time use, 5-minute TTL
- Nonce: 128-bit cryptographically random for replay prevention
- OIDC discovery document cached for 24 hours (retry on failure)
- JWKS cached for 24 hours with automatic refresh
- Token verification: signature, issuer (https://accounts.google.com), audience, expiry (60s tolerance), nonce match, email_verified=true
- Email canonicalization: lowercase, trim, remove dots for Gmail, ignore +suffix
- Strict comparison to ADMIN_GOOGLE_EMAIL (environment variable)
- Redirect allowlist: /admin/dashboard, /admin/contacts, /admin/blogs, /admin/projects, /admin/skills, /admin/experiences, /admin/educations

#### OTP Security
- 8-digit numeric code (100 million combinations)
- Generated with crypto.randomBytes, zero-padded
- Hashed with Argon2id (time=2, memory=65536, parallelism=1) before storage
- Validity: 2 minutes (reduced from 3)
- Maximum 5 attempts per pre-auth session
- Account-level lockout: 10 failed attempts across all IPs within 1 hour (exponential backoff)
- IP-based limits:
  - Generation: 3 per 10 minutes per IP
  - Verification attempts: 10 per 5 minutes per IP
  - Cooldown: 15 minutes after repeated failures
- Resend cooldown: 45 seconds per pre-auth session
- New OTP invalidates all previous for same pre-auth session

#### Session Management
- Absolute TTL: 4 hours from creation (non-extending)
- Idle TTL: 60 minutes (resets on activity within absolute limit)
- Single active session per admin (new session invalidates previous)
- Session data: admin ID, Google email, Google sub, IP hash, user agent, created timestamp, last active timestamp
- Session warnings: at 3h45m remaining and 55m idle
- IP and user agent binding (mismatch requires re-authentication)
- Session invalidation: logout, timeout, security events, session secret rotation

#### Secrets Management
- SESSION_SECRET: 256-bit cryptographically random (crypto.randomBytes(32))
- Rotation: every 90 days with 7-day dual-key validation overlap
- Storage: secrets manager (AWS Secrets Manager or HashiCorp Vault)
- Email provider API keys: rotated every 90 days, failover tested monthly
- Google OAuth client secret: rotated annually, stored in secrets manager

### Rate Limiting
- Multi-factor strategy: IP + browser fingerprint + session
- Distributed rate limiting via Redis (works across server instances)
- Escalation strategy: rate limit → CAPTCHA challenge → temporary ban
- Public GET: 1000/hour/IP
- Contact submit: 5/hour/IP (shadow ban after repeated abuse)
- Auth endpoints:
  - OAuth start: 10/min/IP
  - OTP send: 3/10min/IP + 45s per-session cooldown
  - OTP verify: 10/5min/IP + 5 attempts per pre-auth session
  - Logout: 10/min/IP
- Admin API:
  - Reads: 1000/min/session
  - Writes: 100/hour/session
- Response headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After (on 429)

### File Upload Security
- Allowed: Single PDF file per contact form submission
- Maximum size: 8 MB (enforced at stream level)
- Validation: MIME type (application/pdf) + file extension (.pdf) + magic bytes (%PDF- prefix)
- Processing: streamed to memory buffer (under size limit), SHA-256 computed
- Temporary storage: none on disk during validation; if required, use cryptographically random filename in 0700 directory, delete immediately after processing
- Malware scanning:
  - VirusTotal private scanning mode (community sharing disabled)
  - SHA-256 hash lookup in clean file cache (30-day TTL in Redis)
  - Upload to VT if hash unknown
  - Webhook-based result notification (fallback: polling with exponential backoff, 30s timeout)
  - Status: clean (0 detections) → upload; malicious (≥1 detection) → reject and alert; timeout/inconclusive → reject
- Cloud storage:
  - Cloudinary resource_type=raw, type=authenticated
  - Folder: contact/clean
  - Signed URL generation: SHA-256 signature, 5-minute expiry, transformation allowlist (none for raw PDFs)
  - Lifecycle: auto-delete after 30 days unless explicitly retained
- Deduplication: same SHA-256 reuses cached metadata, skips rescan and reupload

### Anti-Abuse Protections
- **reCAPTCHA v3:** minimum score 0.7; fail-closed with degraded mode fallback
- **Degraded Mode (CAPTCHA outage):** strict rate limit (1/hour/IP) + honeypot + manual review queue
- **Honeypot Fields:** multiple fields with randomized names, CSS visibility hidden, timestamp validation
- **Minimum Interaction Time:** 5 seconds for contact form; maximum 30 minutes (requires re-CAPTCHA)
- **Email Validation:** RFC compliance, MX record verification, disposable email blocklist
- **Generic Responses:** return 200 OK even on anti-abuse failures to prevent information disclosure
- **Shadow Banning:** persistent abusers receive successful responses but submissions ignored

### Logging and Monitoring
- **Structured Logs:** JSON format with timestamp, X-Request-Id, route, method, status, duration, IP hash, user agent
- **Sensitive Data Redaction:** OTP codes, passwords, full IPs (hash with random salt)
- **Log Encryption:** at rest (AES-256) and in transit (TLS)
- **Retention:** 90 days operational logs, 1 year security events, 7 years audit logs
- **Access Control:** RBAC with MFA required for log access
- **Centralized Platform:** aggregation with real-time search and alerting
- **Correlation:** X-Request-Id propagated through all systems

### Alerting
- **Critical Alerts (immediate notification):**
  - Admin login initiated (pre-auth created)
  - Admin login succeeded
  - Admin account locked (OTP attempts exceeded)
  - Malicious file detected (VirusTotal)
  - 5xx error rate > 1% over 5 minutes
  - Database/Redis connection failures
  - Email delivery failure rate > 5%
- **Warning Alerts (batched hourly):**
  - Rate limit violations
  - CAPTCHA failures
  - CSRF token mismatches
  - Geographic anomalies in admin access
  - Clock skew > 30 seconds
- **Operational Alerts (daily summary):**
  - Contact form submission volume
  - Cache hit rates
  - API response time degradation

---

## Data Models

### Database: MongoDB Collections

#### Admins
```
{
  _id: ObjectId,
  googleId: String (unique, indexed),
  email: String (unique, lowercase, indexed),
  name: String,
  profilePicture: String | null,
  lastLogin: Date,
  lastLoginIP: String (HMAC-SHA256 with salt),
  authMetrics: {
    googleAuthSuccess: Number,
    otpGenerated: Number,
    otpResent: Number,
    otpVerified: Number,
    otpFailed: Number,
    totalLogins: Number,
    failedLogins: Number,
    lastOtpGeneratedAt: Date,
    lastFailedAttemptAt: Date,
    recentLoginTimestamps: [Date] (last 10),
    sessionDurations: [Number] (minutes, last 10)
  },
  created_at: Date,
  updated_at: Date
}
Indexes: { email: 1, unique }, { googleId: 1, unique }
```

#### Blogs
```
{
  _id: ObjectId,
  title: String (≤150),
  summary: String (≤300),
  content: String (≤20000),
  slug: String (lowercase, a-z0-9-, 3-100, unique, indexed),
  tags: [String],
  coverImagePath: String,
  coverImageSource: Enum ['local', 'url'],
  referenceLinks: [String],
  isPublic: Boolean (default: true, indexed),
  featured: Boolean (default: false, indexed),
  readCount: Number (default: 0),
  author: ObjectId → admins,
  created_at: Date,
  updated_at: Date
}
Indexes: { slug: 1, unique }, { isPublic: 1, featured: 1, created_at: -1 }, { tags: 1 }
```

#### Projects
```
{
  _id: ObjectId,
  title: String (≤150),
  slug: String (lowercase, a-z0-9-, 3-100, unique, indexed),
  shortDescription: String (≤300),
  description: String (≤20000),
  coverImagePath: String,
  coverImageSource: Enum ['local', 'url'],
  screenshots: [{
    path: String,
    source: Enum ['local', 'url'],
    caption: String (≤150)
  }],
  demo: {
    url: String (HTTPS),
    isActive: Boolean
  },
  github: {
    url: String (HTTPS),
    isActive: Boolean
  },
  technologies: [ObjectId → skills] (referential integrity enforced),
  startDate: Date,
  endDate: Date | null,
  projectType: Enum ['personal', 'freelance', 'open-source', 'client', 'academic'],
  featured: Boolean (default: false, indexed),
  isPublic: Boolean (default: true, indexed),
  created_at: Date,
  updated_at: Date
}
Indexes: { slug: 1, unique }, { isPublic: 1, featured: 1, created_at: -1 }, { technologies: 1 }
```

#### Skills
```
{
  _id: ObjectId,
  name: String (unique, indexed, ≤100),
  category: Enum ['language', 'framework', 'tool', 'platform', 'database', 'soft-skill'],
  iconClass: String (≤50),
  library: Enum ['fontawesome', 'devicons', 'custom'],
  color: String (hex color, ≤7),
  proficiencyPercentage: Number (0-100),
  featured: Boolean (default: false, indexed),
  isPublic: Boolean (default: true, indexed),
  created_at: Date,
  updated_at: Date
}
Indexes: { name: 1, unique }, { category: 1, isPublic: 1 }, { featured: 1 }
Constraint: Cannot delete if referenced by Projects (foreign key check)
```

#### Experiences
```
{
  _id: ObjectId,
  title: String (≤150),
  company: String (≤150),
  location: String (≤150),
  companyWebsite: String (HTTPS) | null,
  startDate: Date,
  endDate: Date | null,
  status: Enum ['current', 'past'],
  description: String (≤2000),
  responsibilities: [String (≤300)],
  achievements: [String (≤300)],
  technologies: [String (≤50)],
  isPublic: Boolean (default: true, indexed),
  created_at: Date,
  updated_at: Date
}
Indexes: { status: 1, isPublic: 1 }, { startDate: -1 }
```

#### Educations
```
{
  _id: ObjectId,
  institution: String (≤150),
  degree: String (≤150),
  field: String (≤150),
  location: String (≤150),
  startDate: Date,
  endDate: Date | null,
  status: Enum ['current', 'completed'],
  grade: {
    value: String (≤20),
    type: Enum ['gpa', 'percentage', 'grade', 'honors'],
    max: String (≤10)
  },
  achievements: [String (≤300)],
  coursework: [String (≤100)],
  activities: [String (≤200)],
  isPublic: Boolean (default: true, indexed),
  created_at: Date,
  updated_at: Date
}
Indexes: { status: 1, isPublic: 1 }, { startDate: -1 }
```

#### Contacts
```
{
  _id: ObjectId,
  name: String (≤120),
  email: String (lowercase, ≤254, indexed),
  phone: String | null (≤20),
  subject: String (≤150),
  message: String (≤2000),
  purpose: Enum ['general', 'job_opportunity', 'collaboration', 'bug_report', 'feedback'],
  details: Object (purpose-specific fields, validated per purpose),
  attachments: [{
    provider: 'cloudinary',
    delivery: 'authenticated',
    public_id: String,
    bytes: Number,
    sha256: String (indexed for deduplication),
    mime: 'application/pdf',
    original_name: String
  }],
  status: Enum ['pending_scan', 'new', 'clean', 'partially_clean', 'rejected'] (indexed),
  response: {
    message: String (≤2000),
    respondedBy: ObjectId → admins,
    respondedAt: Date
  } | null,
  ipHash: String (HMAC-SHA256 with random salt),
  userAgent: String (≤500),
  created_at: Date (indexed, descending),
  updated_at: Date
}
Indexes: { email: 1 }, { purpose: 1 }, { status: 1 }, { created_at: -1 }, { 'attachments.sha256': 1 }
```

### Cache: Redis Key Patterns

All keys prefixed with `app:` namespace. TTL enforcement via Redis expiration.

```
app:session:{session_id} — Hash
  Fields: {adminId, google_email, google_sub, ipHash, ua, created_at, last_active}
  TTL: 4 hours (absolute)

app:admin_current_session:{admin_id} — String
  Value: {session_id}
  TTL: 4 hours (synchronized with session)

app:pre_auth:{pre_auth_id} — Hash
  Fields: {google_email, google_sub, ipHash, ua, created_at, locked}
  TTL: 15 minutes

app:otp:{pre_auth_id} — String
  Value: Argon2id hash of OTP
  TTL: 2 minutes

app:otp_resend_cooldown:{pre_auth_id} — Flag
  TTL: 45 seconds

app:otp_attempts:{pre_auth_id} — Counter
  TTL: 1 hour

app:otp_attempts:{ip_hash} — Counter
  TTL: 1 hour

app:otp_generation:{ip_hash} — Counter
  TTL: 10 minutes

app:otp_cooldown:{ip_hash} — Flag
  TTL: 15 minutes

app:account_lockout:{admin_id} — Counter
  TTL: 1 hour (tracks failed attempts across all IPs)

app:oauth:{state} — JSON
  Value: {nonce, code_verifier, redirect_after_login}
  TTL: 5 minutes

app:contact_count:{ip_hash} — Counter
  TTL: 1 hour

app:clean_file_cache:{sha256} — JSON
  Value: {provider, public_id, bytes, mime, original_name, created_at}
  TTL: 7 days
  Max entries: 10,000 (LRU eviction within namespace)

app:csrf_token:{token_id} — Hash
  Fields: {session_id, created_at}
  TTL: 1 hour (rotated every 15 minutes)

app:idempotency:{key} — Hash
  Fields: {status, response, timestamp}
  TTL: 24 hours

app:rate_limit:{endpoint}:{identifier} — Counter with expiry
  TTL: varies per endpoint (see rate limiting section)
```

Cleanup: Scheduled job runs hourly to remove orphaned keys (Redis SCAN with pattern matching).

---

## API Specification

### Global Conventions

#### Request/Response Format
- **Content-Type:** `application/json` (except contact submit: `multipart/form-data`)
- **Charset:** UTF-8
- **Success Response:**
  ```json
  {
    "success": true,
    "data": {},
    "message": "Operation successful",
    "timestamp": "2025-01-01T00:00:00.000Z",
    "requestId": "uuid-v4"
  }
  ```
- **Error Response:**
  ```json
  {
    "success": false,
    "error": {
      "code": "ERROR_CODE",
      "message": "User-friendly error message",
      "details": {},
      "timestamp": "2025-01-01T00:00:00.000Z",
      "requestId": "uuid-v4"
    }
  }
  ```

#### Standard Headers
- **Request:** `X-Request-Id` (optional; generated if missing)
- **Response:**
  - `X-Request-Id` (correlation ID)
  - `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
  - `Retry-After` (on 429)

#### Pagination
- **Query Parameters:**
  - `page`: integer ≥ 1 (default: 1)
  - `limit`: integer 1-100 (default: 20)
  - `sort`: field name with optional `-` prefix for descending (default: `-created_at`)
- **Response Envelope:**
  ```json
  {
    "data": {
      "items": [],
      "pagination": {
        "page": 1,
        "limit": 20,
        "total": 100,
        "totalPages": 5,
        "hasNext": true,
        "hasPrev": false
      }
    }
  }
  ```

#### Data Validation
- **Strings:** Unicode normalized (NFKC), trimmed, internal whitespace collapsed, control characters removed
- **Emails:** lowercase, RFC 5322 validation, MX record check
- **URLs:** RFC 3986 validation, HTTPS required for external links
- **Slugs:** lowercase a-z0-9-, length 3-100, unique per collection
- **Timestamps:** UTC ISO 8601 with milliseconds
- **ObjectIds:** 24 hex characters, validated before query

#### Error Codes
- `VALIDATION_ERROR` — Request payload validation failed
- `NOT_FOUND` — Resource does not exist
- `UNAUTHORIZED` — Missing or invalid authentication
- `FORBIDDEN` — Insufficient permissions or CSRF failure
- `CONFLICT` — Unique constraint violation (duplicate slug/email)
- `RATE_LIMITED` — Too many requests
- `UNSUPPORTED_MEDIA_TYPE` — Invalid file upload
- `CSRF_ERROR` — CSRF token missing or invalid
- `SERVER_ERROR` — Unexpected server error
- `SERVICE_UNAVAILABLE` — Dependency failure (database, Redis, external service)

#### HTTP Status Codes
- `200 OK` — Successful request
- `201 Created` — Resource created successfully
- `204 No Content` — Successful deletion or logout
- `400 Bad Request` — Validation error
- `401 Unauthorized` — Authentication required or failed
- `403 Forbidden` — Insufficient permissions
- `404 Not Found` — Resource not found
- `409 Conflict` — Duplicate resource
- `415 Unsupported Media Type` — Invalid file type
- `422 Unprocessable Entity` — Semantic validation error
- `423 Locked` — Account locked (too many failed attempts)
- `429 Too Many Requests` — Rate limit exceeded
- `500 Internal Server Error` — Server error
- `502 Bad Gateway` — External service failure
- `503 Service Unavailable` — Temporary unavailability (maintenance, dependency down)

### Public API Endpoints

#### Health Check
```
GET /api/health
Response: 200
{
  "success": true,
  "data": {
    "status": "ok",
    "uptime": 3600,
    "version": "1.0.0",
    "dependencies": {
      "mongodb": "ok",
      "redis": "ok",
      "email": "degraded",
      "cloudinary": "ok"
    }
  }
}
```

#### Blogs
```
GET /api/blogs
Query: page, limit, sort, fields, tag, featured (boolean), search (substring)
Rate: 1000/hour/IP
Response: 200 with pagination
Cache: public, max-age=300, ETag

GET /api/blogs/:slug
Rate: 1000/hour/IP
Response: 200 or 404
Cache: public, max-age=600, ETag
```

#### Projects
```
GET /api/projects
Query: page, limit, sort, fields, technology (skill ObjectId), projectType, featured, search
Rate: 1000/hour/IP
Response: 200 with pagination

GET /api/projects/:slug
Rate: 1000/hour/IP
Response: 200 or 404
```

#### Skills
```
GET /api/skills
Query: page, limit, sort, fields, category, featured, search
Rate: 1000/hour/IP
Response: 200 with pagination

GET /api/skills/:id
Rate: 1000/hour/IP
Response: 200 or 404
```

#### Experiences
```
GET /api/experiences
Query: page, limit, sort, fields, status, company, technology, from (date), to (date)
Rate: 1000/hour/IP
Response: 200 with pagination

GET /api/experiences/:id
Rate: 1000/hour/IP
Response: 200 or 404
```

#### Educations
```
GET /api/educations
Query: page, limit, sort, fields, status, institution, degree, field
Rate: 1000/hour/IP
Response: 200 with pagination

GET /api/educations/:id
Rate: 1000/hour/IP
Response: 200 or 404
```

#### Contact Form
```
POST /api/contact
Content-Type: multipart/form-data
Rate: 5/hour/IP
Headers: X-XSRF-Token (required)
Body:
  - name: string (≤120, required)
  - email: string (≤254, RFC valid, required)
  - phone: string (≤20, optional)
  - subject: string (≤150, optional)
  - message: string (≤2000, required)
  - purpose: enum (required)
  - details: JSON string (purpose-specific, optional)
  - file: File (PDF, ≤8MB, optional)
  - recaptchaToken: string (required)
  - honeypot_field_*: empty (required)
  - submission_start_time: timestamp (required)
Response: 200 (generic success, no details)
{
  "success": true,
  "message": "Thank you for your message. We'll be in touch soon.",
  "timestamp": "2025-01-01T00:00:00.000Z"
}
```

### Authentication API Endpoints

```
POST /api/auth/login
Action: Redirects to /api/auth/google/start
Response: 302

GET /api/auth/google/start
Action: Generates state, nonce, PKCE; redirects to Google OAuth
Rate: 10/min/IP
Response: 302 to Google

GET /api/auth/google/callback
Query: code, state
Action: Validates OAuth callback, creates pre-auth session
Rate: 10/min/IP
Response: 302 to /admin/verify-otp or 403 on failure

POST /api/auth/otp/send
Headers: X-XSRF-Token (required)
Cookie: __Host-pre_auth (required)
Rate: 3/10min/IP + 45s per-session cooldown
Response: 200
{
  "success": true,
  "message": "OTP sent to your email",
  "expiresIn": 120
}

POST /api/auth/otp/verify
Headers: X-XSRF-Token (required)
Cookie: __Host-pre_auth (required)
Body: { "code": "12345678" }
Rate: 10/5min/IP, max 5 attempts per pre-auth
Response: 200
{
  "success": true,
  "data": {
    "redirect": "/admin/dashboard"
  }
}
Errors: 400 (invalid format), 401 (incorrect/expired), 423 (locked)

POST /api/auth/resend-otp
Alias for: POST /api/auth/otp/send

POST /api/auth/logout
Headers: X-XSRF-Token (required)
Cookie: __Host-admin_session (required)
Rate: 10/min/IP
Response: 204 (deletes session and cookies)
```

### Admin API Endpoints

All admin endpoints require:
- Cookie: `__Host-admin_session`
- Header: `X-XSRF-Token` (on mutations)
- Rate limits: 1000 reads/min, 100 writes/hour per session

#### Dashboard
```
GET /api/admin/dashboard
Response: 200
{
  "success": true,
  "data": {
    "counts": {
      "blogs": 42,
      "projects": 15,
      "contacts": {
        "total": 120,
        "new": 5,
        "clean": 100,
        "rejected": 15
      }
    },
    "latest": {
      "contacts": [ /* 5 most recent */ ],
      "blogs": [ /* 5 most recent */ ]
    }
  }
}
```

#### Contacts Management
```
GET /api/admin/contacts
Query: status, purpose, q (name/email search), from, to, page, limit, sort, fields
Response: 200 with pagination

GET /api/admin/contacts/:id
Response: 200 or 404

POST /api/admin/contacts/:id/reply
Body: { "message": string (≤2000) }
Response: 201
{
  "success": true,
  "data": {
    "repliedAt": "2025-01-01T00:00:00.000Z"
  }
}

DELETE /api/admin/contacts/:id
Action: Deletes Cloudinary assets first, then database record, audit log entry
Response: 204 or 424 (cloud delete failed)

GET /api/admin/contacts/:id/attachments/:attachmentId/url
Response: 200
{
  "success": true,
  "data": {
    "url": "https://res.cloudinary.com/...",
    "expiresAt": "2025-01-01T00:05:00.000Z"
  }
}
```

#### Content Management (Blogs, Projects, Skills, Experiences, Educations)
```
GET /api/admin/{resource}
Query: page, limit, sort, fields, isPublic, featured, plus resource-specific filters
Response: 200 with pagination

GET /api/admin/{resource}/:id
Response: 200 or 404

POST /api/admin/{resource}
Headers: Idempotency-Key (optional, ≤64 chars)
Body: resource schema
Response: 201
{
  "success": true,
  "data": {
    "id": "507f1f77bcf86cd799439011"
  }
}

PUT /api/admin/{resource}/:id
Body: partial or full resource schema
Response: 200 with updated resource

DELETE /api/admin/{resource}/:id
Action: Delete cloud assets first (covers, screenshots), referential integrity check, audit log
Response: 204 or 424 (cloud delete failed) or 409 (referential integrity violation)

PATCH /api/admin/{resource}/:id/publish
Body: { "isPublic": boolean, "featured": boolean }
Response: 200 with updated flags
```

---

## Operations

### Deployment Architecture
- **Environment:** Containerized (Docker) on cloud platform (AWS ECS, GCP Cloud Run, or Azure Container Apps)
- **Regions:** Single primary region with read replicas for MongoDB (if needed)
- **Auto-scaling:** CPU-based (target 70%), min 2 instances, max 10
- **Load Balancer:** Application Load Balancer with health checks (/api/health/ready)
- **Secrets:** Stored in AWS Secrets Manager / HashiCorp Vault, injected as environment variables
- **Monitoring:** CloudWatch / Stackdriver for metrics, ELK stack for centralized logging

### Environment Configuration

#### Required Variables
```
# Application
NODE_ENV=production
APP_URL=https://example.com
TRUST_PROXY=true
PORT=3000

# Secrets (from secrets manager)
SESSION_SECRET=<256-bit-hex>

# Database
DATABASE_URL=mongodb+srv://user:pass@cluster.mongodb.net/dbname?tls=true&authMechanism=SCRAM-SHA-256
MONGODB_POOL_MIN=10
MONGODB_POOL_MAX=100

# Redis
REDIS_HOST=redis.example.internal
REDIS_PORT=6379
REDIS_PASSWORD=<strong-password>
REDIS_TLS=true
REDIS_DB=0

# Admin Authentication
ADMIN_GOOGLE_EMAIL=admin@example.com
ADMIN_OTP_EMAIL=admin-otp@example.com
GOOGLE_CLIENT_ID=<client-id>
GOOGLE_CLIENT_SECRET=<secret>
GOOGLE_CALLBACK_URL=https://example.com/api/auth/google/callback

# Email Delivery
PRIMARY_EMAIL_PROVIDER_KEY=<brevo-key-1>
SECONDARY_EMAIL_PROVIDER_KEY=<brevo-key-2>
EMAIL_FROM_ADDRESS=noreply@example.com
EMAIL_FROM_NAME=Example System

# Anti-Abuse
RECAPTCHA_SECRET_KEY=<secret>
RECAPTCHA_MIN_SCORE=0.7

# File Storage
CLOUDINARY_CLOUD_NAME=<cloud-name>
CLOUDINARY_API_KEY=<key>
CLOUDINARY_API_SECRET=<secret>
CLOUDINARY_DELIVERY=authenticated
CLOUDINARY_FOLDER_CONTACT=contact/clean
CLOUDINARY_FOLDER_BLOG_COVERS=blogs/covers
CLOUDINARY_FOLDER_PROJECT_COVERS=projects/covers
CLOUDINARY_FOLDER_PROJECT_SHOTS=projects/screenshots

# Malware Scanning
VIRUSTOTAL_API_KEY=<key>
VIRUSTOTAL_PRIVATE_SCAN=true

# File Processing
TMP_DIR=/var/tmp/app
MAX_FILE_SIZE_MB=8
MAX_BODY_BYTES=10485760

# Alerting
ALERT_WEBHOOK_URL=<slack-webhook-or-similar>

# Optional
JOB_QUEUE_URL=<redis-url-or-sqs-url>
```

### Backup and Recovery
- **MongoDB Backup:**
  - Daily full backup (encrypted with AES-256)
  - Hourly incremental snapshots
  - Point-in-time recovery for last 30 days
  - Backup retention: 30 days daily, 12 months monthly
  - Automated backup testing: monthly with restore validation
- **Redis Backup:**
  - RDB snapshots every 6 hours
  - AOF enabled with fsync every second
  - Snapshots retained for 7 days
- **Recovery Targets:**
  - RTO (Recovery Time Objective): 4 hours
  - RPO (Recovery Point Objective): 1 hour
- **Disaster Recovery Drills:** Quarterly full restore to staging environment

### Monitoring and Alerting
- **Infrastructure Metrics:**
  - CPU, memory, disk I/O, network throughput
  - Container health and restart count
  - Database connection pool utilization
  - Redis memory usage and command latency
- **Application Metrics:**
  - Request rate, error rate (4xx, 5xx), response time (p50, p95, p99)
  - Authentication success/failure rates
  - OTP delivery success rates
  - File upload success/failure rates
  - Cache hit/miss rates
- **Business Metrics:**
  - Contact form submissions (clean, rejected, pending)
  - Public API usage by endpoint
  - Admin activity (logins, content updates)
- **Log Aggregation:**
  - Centralized logging with structured JSON
  - Log retention: 90 days operational, 1 year security
  - Real-time search and filtering
  - Automated log analysis for anomalies
- **Alerting Channels:**
  - Critical: PagerDuty with phone/SMS escalation
  - High: Slack channel with @here mention
  - Medium: Email digest every 4 hours
  - Low: Daily email summary

### Maintenance Windows
- **Scheduled Maintenance:** Sundays 02:00-04:00 UTC (minimal traffic)
- **Emergency Maintenance:** As needed with 1-hour advance notice via status page
- **Database Migrations:** Blue-green deployment with backward compatibility
- **Secret Rotation:**
  - SESSION_SECRET: every 90 days with 7-day overlap
  - Email API keys: every 90 days with provider coordination
  - OAuth client secret: annually with Google coordination
  - Database credentials: semi-annually with zero-downtime rotation

### Housekeeping Jobs
- **Hourly:**
  - Delete orphaned temp files (> 1 hour old)
  - Clean expired Redis keys (SCAN + DEL pattern)
- **Daily:**
  - Cloudinary asset cleanup (delete assets > 30 days old not in database)
  - Update contact statistics for dashboard
  - Backup verification (checksum validation)
- **Weekly:**
  - Database index analysis and optimization recommendations
  - Unused index removal (if zero hits in 30 days)
- **Monthly:**
  - Log rotation and archival
  - Backup restore test to staging
  - Security scan (OWASP ZAP, dependency audit)

### Security Maintenance
- **Dependency Updates:**
  - Automated: Minor and patch versions via Dependabot (weekly)
  - Manual: Major versions with testing (monthly review)
  - Critical security patches: within 24 hours of disclosure
- **Vulnerability Scanning:**
  - npm audit on every commit (CI/CD)
  - Container image scanning (Trivy, Snyk)
  - Monthly penetration testing (automated)
  - Quarterly external security audit
- **Certificate Management:**
  - TLS certificates: automated renewal via Let's Encrypt / ACM
  - Certificate expiry monitoring with 30-day advance alert
  - Annual manual certificate audit

---

## Risk Management

### Identified Risks and Mitigations

#### Critical Risks
1. **Single Admin Lockout**
   - Risk: Admin loses access to Google account or OTP email
   - Mitigation: Emergency break-glass procedure with offline recovery code stored in secure physical location; documented escalation to designated backup administrator
   - Monitoring: Alert on failed login attempts > 3 within 1 hour

2. **Session Secret Compromise**
   - Risk: Session secret leaked; all sessions compromised
   - Mitigation: Secrets stored in secrets manager with access logging; immediate rotation procedure with 7-day dual-key validation; session invalidation on compromise detection
   - Monitoring: Secrets manager access logs; unusual session creation patterns

3. **Database Connection Exhaustion**
   - Risk: Connection pool exhausted; application unavailable
   - Mitigation: Connection pool limits (max 100); connection timeout (10s); slow query monitoring and optimization; read replica for reporting queries
   - Monitoring: Connection pool utilization alerts at 80%

4. **Redis Failure**
   - Risk: Redis unavailable; all sessions lost; authentication disabled
   - Mitigation: Redis cluster with automatic failover; session data persistence with AOF; graceful degradation (read-only mode for public API); health check monitors Redis
   - Monitoring: Redis replication lag; memory usage alerts at 80%

#### High Risks
5. **Email Delivery Failure**
   - Risk: OTP emails not delivered; admin cannot log in
   - Mitigation: Dual email providers with automatic failover; delivery webhook monitoring; 95% delivery SLA tracking; emergency SMS fallback (future enhancement)
   - Monitoring: Email delivery rate alerts below 95%; bounce rate tracking

6. **Malware Detection Bypass**
   - Risk: Malicious file not detected by VirusTotal
   - Mitigation: VirusTotal private scanning with latest engines; manual review queue for suspicious files; user-reported malware tracking; periodic re-scanning of stored files
   - Monitoring: VirusTotal detection rate trends; zero-detection alerts for unusual file patterns

7. **Rate Limiting Bypass**
   - Risk: Distributed botnet bypasses IP-based rate limits
   - Mitigation: Multi-factor rate limiting (IP + fingerprint + behavioral analysis); CAPTCHA challenge escalation; shadow banning; IP reputation scoring
   - Monitoring: Rate limit hit patterns; CAPTCHA failure rates

#### Medium Risks
8. **OAuth Provider Outage**
   - Risk: Google OAuth unavailable; admin cannot authenticate
   - Mitigation: Long-lived admin sessions (4 hours) provide grace period; cached OIDC discovery and JWKS; status page notification; no critical operations requiring immediate auth
   - Monitoring: Google API status; OAuth flow success rates

9. **File Storage Quota Exhaustion**
   - Risk: Cloudinary quota exceeded; file uploads fail
   - Mitigation: Quota monitoring with alerts at 80%; automated cleanup of old attachments; contact form degraded to text-only mode when quota critical
   - Monitoring: Cloudinary usage metrics; daily upload volume trends

10. **Database Performance Degradation**
    - Risk: Slow queries impact user experience
    - Mitigation: Query performance monitoring; index optimization; connection pooling; read replicas for expensive queries; query timeout enforcement
    - Monitoring: Slow query log; query execution time p95 > 500ms alert

### Compliance and Privacy

#### Data Protection
- **Personal Data Collection:** Name, email, phone (optional), IP address (hashed)
- **Data Retention:**
  - Contact records: indefinite with admin-initiated deletion
  - Attachments: 30 days automatic deletion unless retained
  - IP hashes: 90 days then deleted
  - Audit logs: 7 years
- **Data Subject Rights:**
  - Access: Admin can export contact data on request
  - Deletion: Admin can delete contact records and attachments
  - Rectification: Admin can update contact information
  - Portability: JSON export available
- **Privacy by Design:**
  - IP addresses hashed with random salt (not SESSION_SECRET)
  - Minimal data collection (no tracking cookies)
  - No third-party analytics or advertising
  - Data encrypted at rest (MongoDB, logs) and in transit (TLS)

#### Security Compliance
- **OWASP Top 10:** Addressed via security architecture (CSRF, XSS, injection prevention, authentication, etc.)
- **GDPR Considerations:** Data minimization, purpose limitation, storage limitation, integrity, confidentiality
- **SOC 2 Controls:** Access controls, encryption, logging, monitoring, incident response
- **Audit Trail:** Immutable logs for all admin actions, retained 7 years

---

## Acceptance Criteria

### Functional Requirements
- [ ] Admin can authenticate via Google OAuth + OTP and access dashboard
- [ ] Admin can create, read, update, delete blogs with slug-based URLs
- [ ] Admin can create, read, update, delete projects with cover images and screenshots
- [ ] Admin can create, read, update, delete skills with categories and proficiency
- [ ] Admin can create, read, update, delete experiences and educations
- [ ] Admin can view contact submissions with filtering and search
- [ ] Admin can reply to contacts and view PDF attachments via signed URLs
- [ ] Admin can publish/unpublish and feature/unfeature content
- [ ] Public users can browse blogs, projects, skills, experiences, educations via API
- [ ] Public users can submit contact form with optional PDF attachment
- [ ] Public users cannot access unpublished content
- [ ] Public users receive generic success responses (no information disclosure)

### Security Requirements
- [ ] All traffic over HTTPS with HSTS
- [ ] CSP headers prevent XSS attacks
- [ ] CSRF protection on all state-changing endpoints
- [ ] Rate limiting prevents brute-force and abuse
- [ ] OTP limited to 8 attempts total (5 per session + 3 additional with new session)
- [ ] Account lockout after 10 failed OTP attempts across all IPs
- [ ] Session timeout enforced (4h absolute, 60m idle)
- [ ] Single active admin session (previous invalidated)
- [ ] File uploads validated (MIME, extension, magic bytes, size)
- [ ] Malware scanning rejects infected files
- [ ] Cloudinary authenticated delivery prevents unauthorized access
- [ ] IP addresses stored as irreversible hashes
- [ ] Audit logging for all admin actions (immutable)

### Performance Requirements
- [ ] API response time p95 < 500ms for public GET endpoints
- [ ] API response time p95 < 1000ms for admin endpoints
- [ ] Contact form submission response < 2 seconds (async processing)
- [ ] Database queries optimized with proper indexes
- [ ] Connection pooling prevents resource exhaustion
- [ ] Pagination limits prevent large result sets
- [ ] Cache headers enable CDN/browser caching for public content

### Reliability Requirements
- [ ] System uptime > 99.5% (monthly)
- [ ] Graceful handling of Redis outages (public API read-only)
- [ ] Graceful handling of email provider outages (failover)
- [ ] Graceful handling of CAPTCHA outages (degraded mode)
- [ ] Graceful handling of VirusTotal outages (reject uploads with alert)
- [ ] Automatic recovery from transient failures (retry with backoff)
- [ ] Database connection failures don't crash application
- [ ] Health check endpoint accurately reports system status

### Operational Requirements
- [ ] Centralized structured logging with correlation IDs
- [ ] Critical alerts delivered to PagerDuty within 1 minute
- [ ] Backup completion verified daily
- [ ] Backup restore tested monthly with success validation
- [ ] Secrets stored in secrets manager (not environment files)
- [ ] Environment variables validated at startup with clear errors
- [ ] Documentation complete for deployment, configuration, troubleshooting
- [ ] Runbook available for common operational scenarios

### Testing Requirements
- [ ] Unit tests cover > 80% of code
- [ ] Integration tests cover all API endpoints
- [ ] End-to-end tests cover critical user journeys (auth, contact, content management)
- [ ] Security tests validate CSRF, XSS, injection prevention
- [ ] Load tests validate rate limiting and connection pooling
- [ ] Chaos tests validate failure handling (database, Redis, email, CAPTCHA)
- [ ] Accessibility tests validate WCAG 2.1 AA (if frontend included)

---

## File Structure

```
project-root/
├── src/
│   ├── config/
│   │   ├── env.js                    # Environment variable validation
│   │   ├── database.js               # MongoDB connection with pooling
│   │   ├── redis.js                  # Redis client with TLS
│   │   ├── cloudinary.js             # Cloudinary SDK configuration
│   │   └── constants.js              # Application constants
│   ├── models/
│   │   ├── Admin.js                  # Admin schema and methods
│   │   ├── Blog.js
│   │   ├── Project.js
│   │   ├── Skill.js
│   │   ├── Experience.js
│   │   ├── Education.js
│   │   └── Contact.js
│   ├── middleware/
│   │   ├── auth.js                   # Session validation middleware
│   │   ├── csrf.js                   # CSRF protection middleware
│   │   ├── rateLimit.js              # Rate limiting middleware
│   │   ├── validation.js             # Request validation middleware
│   │   ├── errorHandler.js           # Global error handler
│   │   └── securityHeaders.js        # Security headers middleware
│   ├── routes/
│   │   ├── public/
│   │   │   ├── health.js
│   │   │   ├── blogs.js
│   │   │   ├── projects.js
│   │   │   ├── skills.js
│   │   │   ├── experiences.js
│   │   │   ├── educations.js
│   │   │   └── contact.js
│   │   ├── auth/
│   │   │   ├── google.js             # OAuth routes
│   │   │   ├── otp.js                # OTP send/verify
│   │   │   └── logout.js
│   │   └── admin/
│   │       ├── dashboard.js
│   │       ├── contacts.js
│   │       ├── blogs.js
│   │       ├── projects.js
│   │       ├── skills.js
│   │       ├── experiences.js
│   │       └── educations.js
│   ├── controllers/
│   │   ├── public/                   # Public API controllers
│   │   ├── auth/                     # Auth controllers
│   │   └── admin/                    # Admin controllers
│   ├── services/
│   │   ├── googleOAuth.js            # OAuth OIDC implementation
│   │   ├── otp.js                    # OTP generation and verification
│   │   ├── session.js                # Session management
│   │   ├── email.js                  # Email delivery with failover
│   │   ├── recaptcha.js              # reCAPTCHA verification
│   │   ├── virusTotal.js             # VirusTotal API integration
│   │   ├── cloudinary.js             # Cloudinary upload/delete
│   │   ├── fileValidator.js          # File validation (MIME, magic bytes)
│   │   ├── redis.js                  # Redis operations
│   │   └── audit.js                  # Audit logging service
│   ├── jobs/
│   │   ├── contactProcessor.js       # Background job for file scanning
│   │   ├── fileCleanup.js            # Temporary file cleanup
│   │   ├── redisCleanup.js           # Redis key cleanup
│   │   └── cloudinaryCleanup.js      # Old attachment deletion
│   ├── utils/
│   │   ├── validation.js             # Validation utilities
│   │   ├── logger.js                 # Structured logging
│   │   ├── alerts.js                 # Alert webhook integration
│   │   ├── crypto.js                 # Cryptographic utilities
│   │   └── helpers.js                # General helpers
│   ├── app.js                        # Express app setup
│   └── server.js                     # Server bootstrap
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── security/
│   └── load/
├── docs/
│   ├── API.md                        # API documentation
│   ├── SECURITY.md                   # Security documentation
│   ├── DEPLOYMENT.md                 # Deployment guide
│   ├── RUNBOOK.md                    # Operational runbook
│   └── ARCHITECTURE.md               # This document
├── scripts/
│   ├── migrations/                   # Database migration scripts
│   ├── setup-env.sh                  # Environment setup script
│   └── backup-restore.sh             # Backup/restore utility
├── .env.example                      # Example environment variables
├── .gitignore
├── .nvmrc                            # Node.js version specification
├── package.json
├── package-lock.json
├── Dockerfile
├── docker-compose.yml                # Local development environment
├── .dockerignore
└── README.md
```

---

## Testing Strategy

### Unit Tests
- Models: validation, schema methods, virtual fields
- Services: OAuth flow, OTP generation, session management, file validation
- Middleware: authentication, CSRF, rate limiting, validation
- Utilities: crypto functions, validation helpers, logger

### Integration Tests
- Public API: all GET endpoints with pagination, filtering, search
- Auth API: full OAuth flow, OTP send/verify, logout
- Admin API: CRUD operations for all resources, contact management
- File upload: valid/invalid files, malware detection, Cloudinary integration
- Rate limiting: verify limits enforced, headers present
- Error handling: proper status codes and error messages

### End-to-End Tests
- Admin authentication journey: login → OTP → dashboard → logout
- Contact form submission: form fill → file upload → submission → admin view
- Content management journey: create blog → edit → publish → public view → unpublish
- Security: CSRF enforcement, session expiry, rate limiting

### Security Tests
- OWASP ZAP automated scan
- CSRF token validation on all mutations
- SQL/NoSQL injection prevention
- XSS prevention via CSP
- Path traversal prevention in file uploads
- Authentication bypass attempts
- Rate limit bypass attempts

### Load Tests
- Public API: 1000 concurrent users, measure p95/p99 response times
- Contact form: 50 concurrent submissions, verify rate limiting
- Admin API: 10 concurrent admins, measure response times
- Database: connection pool behavior under load
- Redis: session operations under load

### Chaos Tests
- MongoDB unavailable: verify graceful degradation
- Redis unavailable: verify read-only public API
- Email provider unavailable: verify failover
- CAPTCHA unavailable: verify degraded mode
- VirusTotal unavailable: verify safe failure (reject uploads)
- Network partition: verify timeout handling

---

## Future Enhancements

### Scalability Improvements
- Read replicas for MongoDB (separate read/write connections)
- CDN integration for static assets and public API responses
- GraphQL API for flexible client queries
- WebSocket support for real-time notifications
- Microservices architecture (auth service, content service, contact service)

### Feature Additions
- Multi-admin support with role-based access control
- SMS-based OTP as alternative to email
- Content versioning and draft system
- Scheduled publishing for blogs and projects
- Search engine with Elasticsearch for full-text search
- Analytics dashboard with visitor statistics
- Comment system for blogs (with moderation)
- Newsletter subscription and email campaigns

### Security Enhancements
- Hardware security key support (WebAuthn)
- IP geolocation blocking (allowlist specific countries)
- Advanced bot detection (behavioral analysis)
- Content Security Policy violation reporting dashboard
- Automated security scanning in CI/CD pipeline
- Bug bounty program

### Operational Improvements
- Multi-region deployment with global load balancing
- Blue-green deployment automation
- Feature flags for gradual rollouts
- A/B testing framework
- Performance monitoring with distributed tracing
- Cost optimization dashboard
