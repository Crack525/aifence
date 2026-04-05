"""Default sensitive file patterns."""

# Patterns use gitignore-style globs.
# These match filenames/paths that commonly contain secrets.
PATTERNS: list[str] = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "credentials",
    "credentials.*",
    "secrets.json",
    "secrets.yaml",
    "secrets.yml",
    ".secrets",
    ".npmrc",
    ".pypirc",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "service-account*.json",
]
