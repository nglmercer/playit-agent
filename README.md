# The playit program

* Latest Release: 1.0.X
* Offical Website: https://playit.gg
* Offical Downloads: https://playit.gg/download
* Releases: https://github.com/playit-cloud/playit-agent/releases

---

** Non deprecated releases of the playit program:
 `0.17.1` and `1.0.X`

---

## Installation

Download latest release for your platform from https://playit.gg/download and run the installer or binary.

### Installing on Windows

Alternatively, you can install via winget (Windows package manager):

```sh
winget install DevelopedMethods.playit
```

### Installing on Ubuntu or Debian

```sh
curl -SsL https://playit-cloud.github.io/ppa/key.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/playit.gpg >/dev/null
echo "deb [signed-by=/etc/apt/trusted.gpg.d/playit.gpg] https://playit-cloud.github.io/ppa/data ./" | sudo tee /etc/apt/sources.list.d/playit-cloud.list
sudo apt update
sudo apt install playit
```

Getting a warning in apt about playit's repo? Run these commands

```sh
sudo apt-key del '16AC CC32 BD41 5DCC 6F00  D548 DA6C D75E C283 9680'
sudo rm /etc/apt/sources.list.d/playit-cloud.list
sudo apt update

curl -SsL https://playit-cloud.github.io/ppa/key.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/playit.gpg >/dev/null
echo "deb [signed-by=/etc/apt/trusted.gpg.d/playit.gpg] https://playit-cloud.github.io/ppa/data ./" | sudo tee /etc/apt/sources.list.d/playit-cloud.list
sudo apt update
```

**Note**
Please only use the playit program if you downloaded it from an offical source or are compiling and running from source.

### Docker

```sh
docker run --rm -it --net=host -e SECRET_KEY=<secret key> ghcr.io/playit-cloud/playit-agent:latest
```

> [!NOTE]
> Secret key can be generated [here](https://playit.gg/account/setup/wizard/new-account/docker/docker-name).

## Building / Running Locally

Requires Rust: https://rustup.rs

```sh
# Clone the repository
git clone https://github.com/playit-cloud/playit-agent.git
cd playit-agent

# Build and run the release version
cargo run --release
```

## Local programmatic API

The background daemon provides a local JSON-over-IPC API for automation, dashboards, and MCP integrations. It supports tunnel status, tunnel creation/deletion, account state, and browser-based agent claiming without exposing the agent secret to the caller.

See [docs/ipc-api.md](docs/ipc-api.md) for the wire format, operations, and security boundary.

## Embedding Playit

The reusable `playit-runtime` crate exposes the same agent, account, claim,
tunnel, secret, and state behavior directly to another Rust application. The
standalone `playitd` daemon is a host around this runtime that adds IPC and OS
service integration. Embedded operation does not create a Unix socket or a
Windows named pipe.

Add the crate as a path dependency during local development, or pin a known
Git revision for a release:

```toml
playit-runtime = { path = "../playit-agent/packages/playit-runtime" }
# For a release, use a pinned revision instead:
# playit-runtime = { git = "https://github.com/nglmercer/playit-agent", rev = "<known-good-commit>" }
```

The runtime must be started inside the application's existing Tokio runtime.
The host chooses a dedicated secret file, owns logging and signals, and calls
`shutdown` when it is done:

The host should provide Tokio's runtime, macros, networking, synchronization,
and timer features (or simply use `features = ["full"]`):

```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "sync", "time"] }
```

```rust,no_run
use playit_runtime::{PlayitRuntime, RuntimeOptions};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Logging is owned by the embedding application. The runtime does not
    // initialize a global tracing subscriber.
    tracing_subscriber::fmt::init();

    let options = RuntimeOptions {
        secret_path: "./data/playit/secret.toml".into(),
        ..Default::default()
    };
    let (runtime, playit) = PlayitRuntime::start(options).await?;

    let mut events = playit.subscribe();
    let status = playit.status().await;
    println!("{status:?}");

    if !status.has_secret {
        let claim = playit.start_claim().await?;
        println!("Open {} in a browser", claim.claim_url);
    }

    // An application can call account(), list_tunnels(), create_tunnel(),
    // delete_tunnel(), and receive ServiceUpdate values from `events`.
    let _ = &mut events;
    tokio::signal::ctrl_c().await?;
    runtime.shutdown().await?;
    Ok(())
}
```

`PlayitHandle` is cloneable, so an application can pass it to its own service
or HTTP layer. It does not expose the raw secret; use the account, claim,
tunnel, status, lifecycle, statistics, and event APIs instead. Multiple
runtime instances are supported when each has its own secret path and the
underlying Playit account/agent configuration permits them.
