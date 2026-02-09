# Storage load test

**Note:** This requires Python version 3.10+

The tests can execute in three modes:

1. **Direct access**: use a known master secret
2. **Firefox accounts OAuth**: create test accounts and use OAuth JWTs
3. **Self-signed JWT**: generate and sign JWTs locally with a given private key

## Installation

To run it locally:

```bash
poetry install
```

## Mode 1: Direct Access

With a known syncstorage master secret:

```bash
SERVER_URL="http://localhost:8000#secretValue" poetry run molotov --max-runs 5 -cxv loadtest.py
```

## Mode 2: Firefox Accounts OAuth

With FxA stage accounts:

```bash
SERVER_URL="https://token.stage.mozaws.net" \
  FXA_API_HOST="https://api-accounts.stage.mozaws.net" \
  FXA_OAUTH_HOST="https://oauth.stage.mozaws.net" \
  poetry run molotov --workers 3 --duration 60 -v loadtest.py
```

## Mode 3: Self-Signed JWTs

Assuming an RSA keypair was generated, the private key pem was saved and accessible, and the token server was started with the public key JWK configured. The presence of `OAUTH_PRIVATE_KEY_FILE` triggers this mode when using OAuth.

Run with self-signed JWTs:

```bash
SERVER_URL="http://localhost:8000" \
  OAUTH_PRIVATE_KEY_FILE="/path/to/load_test.pem" \
  poetry run molotov --workers 100 --duration 300 -v loadtest.py
```

## Docker

To run it inside docker:

```bash
docker run -e TEST_REPO=https://github.com/mozilla-services/syncstorage-loadtest -e TEST_NAME=test tarekziade/molotov:latest
```

Happy Breaking!
