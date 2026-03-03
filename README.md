# docker-credential-icr

A Docker credential helper for IBM Cloud Container Registry (ICR) that uses OAuth2 web flow for authentication.

## Overview

This credential helper implements the [Docker credential helper protocol](https://github.com/docker/docker-credential-helpers) and performs OAuth2 authentication with IBM Cloud IAM when Docker requests credentials.

For the user, the flow is like this:

1. The user runs a command like `docker pull icr.io/namespace/image:tag` or `docker push icr.io/namespace/image:tag`.
2. A browser window opens and the user is redirected to the IBM Cloud login page.
3. The user logs into IBM Cloud (if not already logged in) and can choose a Trusted Profile.
4. The browser shows a success message.
5. The docker push/pull operation continues.

After the operation, the access token is stored in the credential store of the operating system.
As long as this token is valid, the user is not prompted to log in again.

## Configuration

Configure Docker to use this credential helper by editing `~/.docker/config.json`.
For Podman, edit `~/.config/containers/auth.json` or `/etc/containers/auth.json`.

```json
{
  "credHelpers": {
    "icr.io": "icr",
  }
}
```

**Note**: The helper name is `icr` (without the `docker-credential-` prefix).

## Usage

Once configured, Docker will automatically use this credential helper when pulling or pushing images to ICR:

```bash
# Pull an image - authentication happens automatically
docker pull icr.io/namespace/image:tag

# Push an image - authentication happens automatically
docker push icr.io/namespace/image:tag
```

## Development

1. **Install Rust**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. **Build**:
   ```bash
   cd docker-credential-icr
   cargo build --release
   ```

3. **Cross-compile for other target architectures**:
   ```bash
   cd docker-credential-icr

   # Linux
   cargo build --release --target x86_64-unknown-linux-gnu
   # MacOS
   rustup target add aarch64-apple-darwin
   rustup target add x86_64-apple-darwin
   cargo build --release --target aarch64-apple-darwin
   cargo build --release --target x86_64-apple-darwin
   # Windows
   rustup target add x86_64-pc-windows-gnu
   cargo build --release --target x86_64-pc-windows-gnu
   ```


### Manual Testing

You can test the credential helper manually:

```bash
# Test getting credentials with more log information
export DOCKER_CREDENTIAL_ICR_LOG=debug 
echo "icr.io" | docker-credential-icr get
```
