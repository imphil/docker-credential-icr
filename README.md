# docker-credential-icr

A Docker credential helper for IBM Cloud Container Registry (ICR) that uses OAuth2 web flow for authentication.

## Overview

This credential helper implements the [Docker credential helper protocol](https://docs.docker.com/reference/cli/docker/login/#credential-helper-protocol) and performs OAuth2 authentication with IBM Cloud IAM when Docker requests credentials.

For the user, the flow is like this:

1. The user runs a command like `docker pull icr.io/namespace/image:tag` or `docker push icr.io/namespace/image:tag`.
2. A browser window opens and the user is redirected to the IBM Cloud login page.
3. The user logs into IBM Cloud (if not already logged in) and can choose a Trusted Profile.
4. The browser shows a success message.
5. The docker push/pull operation continues.

After the operation, the access token is stored in the credential store of the operating system.
As long as this token is valid, the user is not prompted to log in again.

## Installation and usage

1. Download the credential helper binary and place it into the `PATH`.

2. Configure Docker or podman to call the IBM Cloud Credential Helper.

   First locate the configuration file that Docker or podman uses:  `~/.docker/config.json` (Docker on Linux/MacOS), `~/.config/containers/auth.json` or `/etc/containers/auth.json` (podman).

   Then edit the config file to add the following section:

   ```json
   {
     "credHelpers": {
       "icr.io": "icr",
     }
   }
   ```

   **Note**: The helper name is `icr` (without the `docker-credential-` prefix).

3. The credential helper will be used automatically when pulling or pushing images from/to ICR.

   ```bash
   # Pull an image - authentication happens automatically
   docker pull icr.io/namespace/image:tag

   # Push an image - authentication happens automatically
   docker push icr.io/namespace/image:tag
   ```

## Development

The easiest way to start development is to [use the Dev Container in this repository](https://code.visualstudio.com/docs/devcontainers/containers#_quick-start-open-a-git-repository-or-github-pr-in-an-isolated-container-volume).

Alternatively, follow the steps below to build the project on a Linux machine.

1. Install Rust
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. Install system dependencies
   ```
   # On Fedora/RHEL.
   dnf install -y gcc gcc-c++ make dbus-devel pkgconf-pkg-config
   ```

2. Build
   ```bash
   # Debug build
   cargo build

   # Release build
   cargo build --release
   ```

### Unit tests

```
cargo test
```

### Manual testing and debugging

You can test the credential helper manually:

```bash
# Test getting credentials with more log information. 
# Valid options are: trace|debug|info|warn|error
export DOCKER_CREDENTIAL_ICR_LOG=debug 
echo "icr.io" | docker-credential-icr get
```

## Contributions and license

The code in this repository is licensed under the [Apache-2.0 license](LICENSE).
Contributions are welcome! Just open an issue or a pull request.
