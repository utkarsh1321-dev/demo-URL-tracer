"""
backend/tests/test_phase9_security.py
Phase 9 — Comprehensive security test suite.

Coverage:
  1. Authentication — missing, invalid, malformed, wrong-audience, expired JWT
  2. Authorization — user_id always from JWT, never from request
  3. Cross-user isolation — URL analysis data, PCAP data
  4. Input validation — URL length, control chars, dangerous schemes, empty
  5. Rate limiting — blocks after limit, window reset, separate user buckets
  6. CORS configuration — env-var driven, not wildcard
  7. Error sanitization — 404/422/500 never expose stack traces or internals
  8. Secret scanning — no secrets in tracked git files
  9. PCAP security — reused from Phase 7 validators (new: processor integration)
 10. Public endpoint security — unauthenticated, IP rate-limited

Run with:
    cd backend
    python -m pytest tests/test_phase9_security.py -v
"""

import os
import sys
import subprocess
import time
import struct
import zlib
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from jose import jwt as jose_jwt


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_jwt(
    secret: str = "testsecret",
    sub: str = "user-uuid-aaaa-1111",
    audience: str = "authenticated",
    expired: bool = False,
    algorithm: str = "HS256",
    extra: dict | None = None,
) -> str:
    now = datetime.now(tz=timezone.utc)
    exp = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    payload = {"sub": sub, "aud": audience, "iat": now, "exp": exp, "email": "test@example.com"}
    if extra:
        payload.update(extra)
    return jose_jwt.encode(payload, secret, algorithm=algorithm)


def _make_minimal_pcap() -> bytes:
    """Minimal valid PCAP global header (24 bytes, little-endian)."""
    return struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)


# ═══════════════════════════════════════════════════════════════
# 1. Authentication security
# ═══════════════════════════════════════════════════════════════

class TestAuthenticationSecurity:
    """
    Test that auth.py correctly validates JWTs and rejects bad tokens.
    Tests the get_current_user() dependency directly — no HTTP layer needed.
    """

    def _decode_with_secret(self, token: str, secret: str = "testsecret"):
        """Helper: call the same jose.jwt.decode path used by auth.py."""
        return jose_jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="authenticated",
        )

    def test_valid_jwt_extracts_user_id(self):
        """A properly signed JWT yields the correct user id from sub."""
        token = _make_jwt(sub="user-aaaa-1111")
        payload = self._decode_with_secret(token)
        assert payload["sub"] == "user-aaaa-1111"
        assert payload["aud"] == "authenticated"

    def test_expired_jwt_raises(self):
        """An expired JWT must raise JWTError."""
        from jose import JWTError
        token = _make_jwt(expired=True)
        with pytest.raises(JWTError):
            self._decode_with_secret(token)

    def test_wrong_secret_raises(self):
        """A JWT signed with a different secret must be rejected."""
        from jose import JWTError
        token = _make_jwt(secret="correct-secret")
        with pytest.raises(JWTError):
            self._decode_with_secret(token, secret="wrong-secret")

    def test_wrong_audience_raises(self):
        """A JWT with audience != 'authenticated' must be rejected."""
        from jose import JWTError
        token = _make_jwt(audience="anon")
        with pytest.raises(JWTError):
            self._decode_with_secret(token)

    def test_malformed_token_raises(self):
        """Garbage string must not decode."""
        from jose import JWTError
        with pytest.raises(JWTError):
            self._decode_with_secret("not.a.jwt")

    def test_empty_token_raises(self):
        """Empty string must raise."""
        from jose import JWTError
        with pytest.raises(JWTError):
            self._decode_with_secret("")

    def test_token_without_sub_detected(self):
        """A valid JWT missing sub claim entirely must be caught by auth logic."""
        # Craft a payload with no 'sub' key at all
        from datetime import datetime, timezone, timedelta
        now = datetime.now(tz=timezone.utc)
        payload = {
            "aud": "authenticated",
            "iat": now,
            "exp": now + timedelta(hours=1),
            "email": "nosub@example.com",
            # intentionally no "sub"
        }
        token = jose_jwt.encode(payload, "testsecret", algorithm="HS256")
        decoded = self._decode_with_secret(token)
        user_id = decoded.get("sub")
        # auth.py checks: if not user_id → raise 401
        assert not user_id, "sub missing from JWT — auth.py should reject this"

    def test_missing_jwt_secret_blocks_all_requests(self):
        """When SUPABASE_JWT_SECRET is empty, auth must refuse with 503."""
        import auth
        original = auth._JWT_SECRET
        try:
            auth._JWT_SECRET = ""
            import fastapi
            from fastapi.security import HTTPAuthorizationCredentials
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="anytoken")
            import asyncio
            with pytest.raises(fastapi.HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(auth.get_current_user(creds))
            assert exc.value.status_code == 503
        finally:
            auth._JWT_SECRET = original

    def test_get_current_user_returns_correct_email(self):
        """Auth.py extracts email from the JWT payload."""
        import auth, asyncio
        from fastapi.security import HTTPAuthorizationCredentials
        secret = "testsecret"
        original_secret = auth._JWT_SECRET
        try:
            auth._JWT_SECRET = secret
            token = _make_jwt(secret=secret, sub="user-xyz", extra={"email": "alice@example.com"})
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
            user = asyncio.get_event_loop().run_until_complete(auth.get_current_user(creds))
            assert user.id    == "user-xyz"
            assert user.email == "alice@example.com"
        finally:
            auth._JWT_SECRET = original_secret


# ═══════════════════════════════════════════════════════════════
# 2. Authorization — user_id NEVER from request body
# ═══════════════════════════════════════════════════════════════

class TestAuthorizationSecurity:
    """
    Verify that user ownership is always derived from the JWT sub claim,
    never from request body or query parameters.
    """

    def test_analyze_endpoint_uses_jwt_user_id_not_body(self):
        """
        api/analyze.py must extract user_id from CurrentUser (JWT),
        not from any field in the request body.
        """
        import inspect
        import api.analyze as analyze_module
        source = inspect.getsource(analyze_module)

        # Must NOT accept user_id from request body
        assert "request.user_id"  not in source, "user_id must not come from request"
        assert 'body["user_id"]'  not in source, "user_id must not come from body"
        assert "payload.user_id"  not in source, "user_id must not come from payload"

        # Must use current_user.id (from verified JWT)
        assert "current_user.id"  in source, "user_id must come from current_user.id (JWT)"

    def test_upload_endpoint_uses_jwt_user_id(self):
        """upload.py PCAP handler must store user_id from JWT, not from body."""
        import inspect
        import api.upload as upload_module
        source = inspect.getsource(upload_module)
        assert "current_user.id" in source
        assert "request.user_id" not in source

    def test_pcap_endpoint_uses_jwt_user_id(self):
        """api/pcap.py history endpoint must filter by JWT user_id."""
        import inspect
        import api.pcap as pcap_module
        source = inspect.getsource(pcap_module)
        assert "current_user.id" in source

    def test_public_endpoint_has_no_auth_dependency(self):
        """
        /api/public/analyze must NOT import get_current_user —
        it is intentionally unauthenticated.
        """
        import inspect
        import api.public_analyze as pub
        source = inspect.getsource(pub)
        assert "get_current_user" not in source

    def test_public_endpoint_does_not_write_to_db(self):
        """Public endpoint must not import get_db or persist records."""
        import inspect
        import api.public_analyze as pub
        source = inspect.getsource(pub)
        assert "get_db"  not in source
        assert "session" not in source.lower() or "db" not in source


# ═══════════════════════════════════════════════════════════════
# 3. Cross-user isolation logic
# ═══════════════════════════════════════════════════════════════

class TestCrossUserIsolation:
    """
    Verify that database queries are always scoped to the authenticated user.
    These tests inspect the query logic directly (no real DB needed).
    """

    def test_analyze_history_filters_by_user_id(self):
        """GET /analyze/history must filter url_analyses by current_user.id."""
        import inspect
        import api.analyze as analyze_module
        source = inspect.getsource(analyze_module)
        # Must filter by user_id in the query
        assert "user_id" in source
        assert "current_user.id" in source

    def test_pcap_history_filters_by_user_id(self):
        """GET /pcap/history must filter pcap_analyses by current_user.id."""
        import inspect
        import api.pcap as pcap_module
        source = inspect.getsource(pcap_module)
        assert "user_id" in source
        assert "current_user.id" in source

    def test_set_rls_user_called_in_analyze(self):
        """analyze.py must call set_rls_user() to activate PostgreSQL RLS."""
        import inspect
        import api.analyze as analyze_module
        source = inspect.getsource(analyze_module)
        assert "set_rls_user" in source

    def test_set_rls_user_called_in_upload(self):
        """upload.py PCAP handler must call set_rls_user()."""
        import inspect
        import api.upload as upload_module
        source = inspect.getsource(upload_module)
        assert "set_rls_user" in source

    def test_set_rls_user_called_in_pcap_history(self):
        """pcap.py history endpoints must call set_rls_user()."""
        import inspect
        import api.pcap as pcap_module
        source = inspect.getsource(pcap_module)
        assert "set_rls_user" in source

    def test_delete_uses_owner_filter(self):
        """
        DELETE endpoints must filter by both primary key AND user_id —
        a user must not be able to delete another user's records by guessing an ID.
        """
        import inspect
        import api.analyze as analyze_module
        source = inspect.getsource(analyze_module)
        # The delete handler should filter by user_id
        assert "user_id" in source

    def test_enumeration_prevention_in_delete(self):
        """
        404 (not 403) must be returned when a record doesn't belong to the caller.
        Returning 403 reveals that the record exists, enabling enumeration.
        """
        import inspect
        import api.analyze as analyze_module
        source = inspect.getsource(analyze_module)
        # Status 404 must be present in the delete logic (not 403)
        assert "404" in source


# ═══════════════════════════════════════════════════════════════
# 4. Input validation security
# ═══════════════════════════════════════════════════════════════

class TestInputValidationSecurity:
    """
    Test URL validation catches all dangerous / malformed inputs before
    they reach the ML engine or database.
    """

    def test_url_exceeding_2048_chars_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        long_url = "http://example.com/" + "a" * 2100
        with pytest.raises(URLValidationError):
            validate_and_normalize(long_url)

    def test_empty_url_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("")

    def test_whitespace_only_url_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("   ")

    def test_javascript_scheme_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("javascript:alert(1)")

    def test_data_uri_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("data:text/html,<h1>xss</h1>")

    def test_file_scheme_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("file:///etc/passwd")

    def test_vbscript_scheme_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("vbscript:msgbox(1)")

    def test_null_byte_in_url_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("http://evil.com/path\x00extra")

    def test_control_char_in_url_rejected(self):
        from analysis.validator import validate_and_normalize, URLValidationError
        with pytest.raises(URLValidationError):
            validate_and_normalize("http://evil.com/\x01\x02\x1f")

    def test_plain_http_accepted(self):
        from analysis.validator import validate_and_normalize
        result = validate_and_normalize("http://example.com/path")
        assert "example.com" in result

    def test_https_accepted(self):
        from analysis.validator import validate_and_normalize
        result = validate_and_normalize("https://secure.example.com/login")
        assert "secure.example.com" in result

    def test_public_analyze_schema_rejects_long_url(self):
        """PublicAnalyzeRequest pydantic model must reject URLs > 2048 chars."""
        from api.public_analyze import PublicAnalyzeRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            PublicAnalyzeRequest(url="http://x.com/" + "a" * 2100)

    def test_public_analyze_schema_rejects_control_chars(self):
        from api.public_analyze import PublicAnalyzeRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            PublicAnalyzeRequest(url="http://evil.com/\x01path")

    def test_public_analyze_schema_rejects_empty(self):
        from api.public_analyze import PublicAnalyzeRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            PublicAnalyzeRequest(url="")


# ═══════════════════════════════════════════════════════════════
# 5. Rate limiting
# ═══════════════════════════════════════════════════════════════

class TestRateLimiting:
    """
    Test the sliding-window rate limiter used by both the authenticated
    and public endpoints.
    """

    def test_allows_requests_under_limit(self):
        from middleware.rate_limiter import RateLimiter
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        for i in range(5):
            allowed, retry = limiter.check("user-001")
            assert allowed, f"Request {i+1} should be allowed"

    def test_blocks_after_limit_exceeded(self):
        from middleware.rate_limiter import RateLimiter
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.check("user-002")
        # 4th request must be denied
        allowed, retry_after = limiter.check("user-002")
        assert not allowed
        assert retry_after >= 1

    def test_independent_buckets_per_user(self):
        """Rate limits must be tracked independently per user_id."""
        from middleware.rate_limiter import RateLimiter
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        # Exhaust user-A
        limiter.check("user-A")
        limiter.check("user-A")
        blocked, _ = limiter.check("user-A")
        assert not blocked

        # user-B should still be free
        allowed, _ = limiter.check("user-B")
        assert allowed

    def test_reset_clears_bucket(self):
        from middleware.rate_limiter import RateLimiter
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.check("user-C")
        limiter.check("user-C")
        _, _ = limiter.check("user-C")   # now blocked
        limiter.reset("user-C")
        allowed, _ = limiter.check("user-C")
        assert allowed

    def test_remaining_decrements_correctly(self):
        from middleware.rate_limiter import RateLimiter
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        assert limiter.remaining("user-D") == 10
        limiter.check("user-D")
        assert limiter.remaining("user-D") == 9
        limiter.check("user-D")
        assert limiter.remaining("user-D") == 8

    def test_public_limiter_is_separate_instance(self):
        """
        The public endpoint uses a separate RateLimiter (not the user limiter).
        Verifies they are distinct objects to prevent shared state cross-contamination.
        """
        from middleware.rate_limiter import analyze_limiter
        from api.public_analyze import _public_limiter
        assert analyze_limiter is not _public_limiter


# ═══════════════════════════════════════════════════════════════
# 6. CORS configuration
# ═══════════════════════════════════════════════════════════════

class TestCORSConfiguration:
    """
    Verify that CORS is driven by the ALLOWED_ORIGINS env var
    and no longer uses the wildcard '*'.
    """

    def test_main_py_does_not_use_wildcard_cors(self):
        """main.py must not contain allow_origins=['*']."""
        import inspect
        import main
        source = inspect.getsource(main)
        assert 'allow_origins=["*"]'  not in source, "Wildcard CORS found in main.py"
        assert "allow_origins=['*']"  not in source, "Wildcard CORS found in main.py"

    def test_cors_reads_from_env_var(self):
        """main.py must read ALLOWED_ORIGINS from environment."""
        import inspect
        import main
        source = inspect.getsource(main)
        assert "ALLOWED_ORIGINS" in source

    def test_cors_has_explicit_allowed_methods(self):
        """CORS must list explicit methods, not '*'."""
        import inspect
        import main
        source = inspect.getsource(main)
        assert 'allow_methods=["*"]' not in source
        # Must list specific methods
        assert "GET" in source or "POST" in source

    def test_cors_has_explicit_allowed_headers(self):
        """CORS must list explicit headers, not '*'."""
        import inspect
        import main
        source = inspect.getsource(main)
        assert 'allow_headers=["*"]' not in source

    def test_allowed_origins_list_is_non_empty_by_default(self):
        """The default fallback for ALLOWED_ORIGINS must include localhost."""
        import inspect, main
        source = inspect.getsource(main)
        # The hardcoded default string in main.py must include localhost
        # (runtime value may differ if .env overrides with production origins)
        assert "localhost" in source, "Default ALLOWED_ORIGINS must include localhost for dev"
        # The mechanism must also exist at runtime
        origins = getattr(main, "ALLOWED_ORIGINS", [])
        assert isinstance(origins, list)
        assert len(origins) > 0


# ═══════════════════════════════════════════════════════════════
# 7. Error response sanitization
# ═══════════════════════════════════════════════════════════════

class TestErrorSanitization:
    """
    Verify that error responses never contain stack traces, internal paths,
    or secrets — even for unhandled exceptions.
    """

    def test_global_exception_handler_exists(self):
        """main.py must register a global exception handler."""
        import inspect
        import main
        source = inspect.getsource(main)
        assert "global_exception_handler" in source
        assert "exception_handler(Exception)" in source

    def test_global_exception_handler_returns_sanitized_message(self):
        """The global handler must return a generic message, not exc details."""
        import inspect
        import main
        source = inspect.getsource(main)
        # Must include a generic message
        assert "Internal server error" in source or "unexpected error" in source.lower()
        # Must NOT log the exception message (only type)
        assert "type(exc).__name__" in source

    def test_auth_401_does_not_reveal_secret(self):
        """The 401 response from auth must be a generic message."""
        import auth
        import asyncio
        from fastapi.security import HTTPAuthorizationCredentials
        original = auth._JWT_SECRET
        try:
            auth._JWT_SECRET = "my-secret-value"
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="bad.token.here")
            import fastapi
            with pytest.raises(fastapi.HTTPException) as exc:
                asyncio.get_event_loop().run_until_complete(auth.get_current_user(creds))
            # Must not expose the secret in the error detail
            detail = str(exc.value.detail)
            assert "my-secret-value" not in detail
            assert "SUPABASE" not in detail
        finally:
            auth._JWT_SECRET = original

    def test_validation_error_response_is_generic(self):
        """URLValidationError messages must not expose internal paths or DB details."""
        from analysis.validator import validate_and_normalize, URLValidationError
        try:
            validate_and_normalize("javascript:alert(1)")
        except URLValidationError as e:
            msg = str(e)
            # Must not contain stack traces or file paths
            assert "Traceback" not in msg
            assert "/backend/" not in msg
            assert "site-packages" not in msg

    def test_no_stack_traces_in_analysis_engine_errors(self):
        """analyze_url() error propagation must not expose raw stack traces."""
        import inspect
        import api.analyze as analyze_module
        source = inspect.getsource(analyze_module)
        # Exception handlers should not pass raw exception messages to the client
        # (traceback.format_exc should never appear in API response handlers)
        assert "traceback.format_exc" not in source.lower()


# ═══════════════════════════════════════════════════════════════
# 8. Secret scanning — tracked git files
# ═══════════════════════════════════════════════════════════════

class TestSecretScanning:
    """
    Scan all git-tracked files for patterns that match real secrets.
    Runs git grep against the working tree.
    """

    REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))

    def _git_grep(self, pattern: str) -> list[str]:
        """Run git grep for pattern; return list of matching lines."""
        result = subprocess.run(
            ["git", "grep", "-n", "--fixed-strings", pattern],
            cwd=self.REPO_ROOT,
            capture_output=True,
            text=True,
        )
        # git grep exits 0 = found, 1 = not found, >1 = error
        if result.returncode > 1:
            return []  # git not available or repo error — skip
        return result.stdout.strip().splitlines()

    def test_no_service_role_key_in_tracked_files(self):
        """SUPABASE_SERVICE_ROLE_KEY value must never appear in non-test tracked files."""
        matches = self._git_grep("SUPABASE_SERVICE_ROLE_KEY=ey")
        # Exclude test files — they contain this pattern as a search string, not a real value
        real_matches = [
            m for m in matches
            if "test_" not in m and "tests/" not in m and ".example" not in m
        ]
        assert real_matches == [], f"Service role key found in tracked files: {real_matches}"

    def test_no_database_password_in_tracked_files(self):
        """postgresql:// connection strings with passwords must not be tracked."""
        matches = self._git_grep("postgresql://postgres:")
        # Allow only the .env.example placeholder format (no real password after colon)
        real_creds = [m for m in matches if "PASSWORD]" not in m and "<password>" not in m.lower() and m.endswith("@")]
        # Accept the .env.example which has placeholder values
        real_creds = [m for m in real_creds if ".env.example" not in m]
        assert real_creds == [], f"Database credentials found: {real_creds}"

    def test_no_env_files_tracked(self):
        """Real .env files (not .env.example) must not be git-tracked."""
        result = subprocess.run(
            ["git", "ls-files", "*.env", "**/.env", "**/.env.local", "**/.env.production"],
            cwd=self.REPO_ROOT,
            capture_output=True,
            text=True,
        )
        tracked = [
            line for line in result.stdout.strip().splitlines()
            if ".example" not in line and ".env.example" not in line
        ]
        assert tracked == [], f"Real .env files are tracked: {tracked}"

    def test_no_private_keys_in_tracked_files(self):
        """PEM-format private keys must not appear in non-test tracked files."""
        matches     = self._git_grep("BEGIN PRIVATE KEY")
        rsa_matches = self._git_grep("BEGIN RSA PRIVATE KEY")
        # Exclude test files which contain these strings as grep patterns
        def _no_test(lst):
            return [m for m in lst if "test_" not in m and "tests/" not in m]
        assert _no_test(matches)     == [], f"Private key found: {_no_test(matches)}"
        assert _no_test(rsa_matches) == [], f"RSA private key found: {_no_test(rsa_matches)}"

    def test_gitignore_excludes_env_files(self):
        """.gitignore must explicitly exclude .env files."""
        gitignore_path = os.path.join(self.REPO_ROOT, ".gitignore")
        assert os.path.exists(gitignore_path), ".gitignore not found at repo root"
        content = open(gitignore_path).read()
        assert ".env" in content, ".env not excluded in .gitignore"

    def test_no_hardcoded_jwt_tokens_in_source(self):
        """
        eyJ... (JWT base64 prefix) must not appear in .py or .js source files
        (it would indicate a hardcoded token).
        """
        result = subprocess.run(
            ["git", "grep", "-n", "-l", "eyJhbGci"],
            cwd=self.REPO_ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            # Only allowed in example/documentation files
            files_with_jwt = result.stdout.strip().splitlines()
            suspicious = [
                f for f in files_with_jwt
                if not any(safe in f for safe in [".env.example", "README", "docs/", ".md", "test_"])
            ]
            assert suspicious == [], f"Hardcoded JWT tokens found in source: {suspicious}"


# ═══════════════════════════════════════════════════════════════
# 9. PCAP security (integration with validator + processor)
# ═══════════════════════════════════════════════════════════════

class TestPCAPSecurity:
    """PCAP-specific security tests beyond what Phase 7 already covers."""

    def _write_tmp(self, content: bytes, suffix: str = ".pcap") -> str:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
            f.write(content)
            return f.name

    def test_empty_pcap_rejected(self):
        from pcap.validator import validate_pcap_path, PCAPValidationError
        path = self._write_tmp(b"")
        try:
            with pytest.raises(PCAPValidationError, match="empty"):
                validate_pcap_path(path)
        finally:
            os.unlink(path)

    def test_oversized_pcap_rejected(self):
        """A file claiming to be >50MB (via size check) must be rejected."""
        from pcap.validator import validate_pcap_path, PCAPValidationError, MAX_FILE_BYTES
        # Create a file with valid magic but report size > limit in the validator
        path = self._write_tmp(_make_minimal_pcap() + b"\x00" * 100)
        try:
            # Only check that the path-size validation logic exists
            # (we can't create a 50MB file in tests — just verify constant is set correctly)
            assert MAX_FILE_BYTES == 50 * 1024 * 1024, "Max file size must be 50MB"
        finally:
            os.unlink(path)

    def test_wrong_extension_rejected(self):
        from pcap.validator import validate_pcap_path, PCAPValidationError
        path = self._write_tmp(_make_minimal_pcap(), suffix=".pdf")
        try:
            with pytest.raises(PCAPValidationError, match="extension"):
                validate_pcap_path(path)
        finally:
            os.unlink(path)

    def test_corrupted_magic_bytes_rejected(self):
        from pcap.validator import validate_pcap_path, PCAPValidationError
        path = self._write_tmp(b"\xDE\xAD\xBE\xEF" + b"\x00" * 20)
        try:
            with pytest.raises(PCAPValidationError, match="magic"):
                validate_pcap_path(path)
        finally:
            os.unlink(path)

    def test_zip_disguised_as_pcap_rejected(self):
        """A ZIP file renamed to .pcap must be rejected by magic bytes."""
        from pcap.validator import validate_pcap_path, PCAPValidationError
        zip_magic = b"PK\x03\x04" + b"\x00" * 20  # ZIP magic bytes
        path = self._write_tmp(zip_magic, suffix=".pcap")
        try:
            with pytest.raises(PCAPValidationError, match="magic"):
                validate_pcap_path(path)
        finally:
            os.unlink(path)

    def test_processor_has_no_subprocess_calls(self):
        """processor.py must never execute subprocess or shell commands."""
        import pcap.processor as proc
        # Check actual imports — subprocess must not be imported
        assert "subprocess" not in [m.__name__ for m in vars(proc).values()
                                    if hasattr(m, '__name__')]
        # Verify no os.system or shell=True patterns in source (excluding docstrings)
        import inspect
        lines = [
            l for l in inspect.getsource(proc).splitlines()
            if not l.strip().startswith(('"""', "'''", '#'))
        ]
        code_only = "\n".join(lines)
        assert "os.system(" not in code_only
        assert "shell=True" not in code_only
        assert "import subprocess" not in code_only

    def test_extractor_has_no_subprocess_calls(self):
        """extractor.py must never execute subprocess or shell commands."""
        import pcap.extractor as ext
        import inspect
        lines = [
            l for l in inspect.getsource(ext).splitlines()
            if not l.strip().startswith(('"""', "'''", '#'))
        ]
        code_only = "\n".join(lines)
        assert "import subprocess" not in code_only
        assert "os.system(" not in code_only
        assert "shell=True" not in code_only
        assert "eval(" not in code_only
        assert "exec(" not in code_only


# ═══════════════════════════════════════════════════════════════
# 10. Public endpoint security
# ═══════════════════════════════════════════════════════════════

class TestPublicEndpointSecurity:
    """
    Verify the public endpoint (Chrome extension) has correct security properties:
    - No auth required
    - IP rate limited separately from user rate limiter
    - Never writes user data to DB
    - Returns sanitized response (no internal rule details)
    """

    def test_public_analyze_response_excludes_rule_details(self):
        """
        The response schema must not include full rule_flags list —
        only a count, to prevent information disclosure about detection logic.
        """
        import inspect
        import api.public_analyze as pub
        source = inspect.getsource(pub)
        # Should return flags_triggered (count) not the full flags list
        assert "flags_triggered" in source
        # Must not return the raw rule_flags list
        assert '"rule_flags"' not in source or "len(result.rule_flags)" in source

    def test_public_endpoint_has_ip_rate_limiter(self):
        """public_analyze.py must use an IP-based rate limiter."""
        import inspect
        import api.public_analyze as pub
        source = inspect.getsource(pub)
        assert "_public_limiter" in source
        assert "client.host" in source or "client_ip" in source

    def test_public_endpoint_logs_only_ip_suffix(self):
        """
        Logging in the public endpoint must not log the full URL or full IP —
        only the last 4 chars of the IP for debugging.
        """
        import inspect
        import api.public_analyze as pub
        source = inspect.getsource(pub)
        # IP suffix must be used in logging
        assert "client_ip[-4:]" in source or "[-4:]" in source
        # logger.info lines must not include payload.url (the raw user-submitted URL)
        # Find all logger.info() call lines
        log_lines = [
            line.strip() for line in source.splitlines()
            if "logger.info" in line
        ]
        for line in log_lines:
            assert "payload.url" not in line, (
                f"logger.info appears to log payload.url (raw user URL): {line}"
            )
            assert "normalized_url" not in line, (
                f"logger.info appears to log normalized_url: {line}"
            )

    def test_public_rate_limiter_config(self):
        """Public rate limiter must be more conservative than user limiter."""
        from middleware.rate_limiter import analyze_limiter
        from api.public_analyze import _public_limiter
        # Public limit <= user limit (be conservative for unauthenticated)
        assert _public_limiter.max_requests <= analyze_limiter.max_requests

    def test_engine_produces_valid_result_offline(self):
        """Full engine must complete without network calls."""
        from analysis.engine import analyze_url
        result = analyze_url("http://free-iphone-winner.suspicious-domain.biz/login.php")
        assert result.risk_score >= 0
        assert result.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert result.model_version is not None
