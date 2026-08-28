# Local JSON IPC API

`playitd` exposes a local, line-delimited JSON API over its existing IPC transport. It uses a Unix socket on Linux/macOS and a restricted Windows Named Pipe. The default endpoint is the same one used by `playit attach` and `playit status`.

The first server frame is a `hello` envelope. Each request is one JSON object terminated by a newline.

`status.phase` may be `reconnecting` while the runtime is recovering its
Playit control connection. This is a live service state, not an account or
secret failure; the runtime keeps retrying and returns to `running` when the
control connection is healthy again.

```json
{
  "ipc_version": 3,
  "request_id": 1,
  "request": { "type": "get_tunnels" }
}
```

Responses use the matching `request_id`:

```json
{
  "message_kind": "response",
  "data": {
    "ipc_version": 3,
    "request_id": 1,
    "response": {
      "type": "tunnels",
      "data": { "tunnels": [], "pending_tunnels": [] }
    }
  }
}
```

## Operations

`get_status` returns daemon health and socket metadata. `get_state` returns the lifecycle and the current agent snapshot.

`get_tunnels` returns the current tunnel and pending-tunnel list:

```json
{"ipc_version":3,"request_id":2,"request":{"type":"get_tunnels"}}
```

`create_tunnel` creates a one-port tunnel assigned to the running agent. `protocol` accepts `tcp`, `udp`, or `both`; `local_address` defaults to `127.0.0.1`:

```json
{
  "ipc_version": 3,
  "request_id": 3,
  "request": {
    "type": "create_tunnel",
    "local_port": 25565,
    "protocol": "tcp",
    "local_address": "127.0.0.1",
    "name": "minecraft"
  }
}
```

The response contains the cloud tunnel UUID. The daemon refreshes its local state automatically.

`delete_tunnel` removes a tunnel by UUID:

```json
{
  "ipc_version": 3,
  "request_id": 4,
  "request": {
    "type": "delete_tunnel",
    "tunnel_id": "00000000-0000-0000-0000-000000000000"
  }
}
```

`get_account` returns account status, agent ID, guest login link, and any active claim URL. For an unconfigured daemon, call `start_claim`; it returns a claim URL and automatically provisions the secret after the browser approval:

```json
{"ipc_version":3,"request_id":5,"request":{"type":"start_claim"}}
```

Each tunnel reports `local_address` as the origin host or IP address without a
port. `local_port` contains the origin port for a single-port tunnel and is
`null` when the origin has multiple protocol-specific ports. `destination` is
a display string and is not intended to be parsed by clients.

## Security

This API intentionally binds only to local IPC. On Linux the daemon restricts
the socket to owner/group mode `0660` and uses the `playit` service group for a
root-owned service. On macOS it uses owner-only mode `0600`. Windows uses a
restricted Named Pipe ACL granting access only to SYSTEM, Administrators, and
the installed user's SID; Authenticated Users are not granted access. The
Windows installer also protects the data directory and `installed_user.sid`
file with SYSTEM/Administrators-only DACLs because that file is used to build
the pipe ACL. These endpoint permissions are the access control boundary. Any
process that can access the endpoint can manage that agent's tunnels and
account setup, so the socket must not be forwarded or exposed as a network
listener.
