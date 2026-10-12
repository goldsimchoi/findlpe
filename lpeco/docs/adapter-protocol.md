# External adapter protocol

LPECO starts an adapter subprocess and speaks JSON-RPC 2.0, one complete JSON
object per UTF-8 line. The subprocess reserves stdout for responses and may use
stderr for bounded diagnostics. Protocol version `1` requires async tasks.

Every request has this envelope:

```json
{"jsonrpc":"2.0","id":"1","method":"handshake","params":{}}
```

Every response repeats the string ID and contains exactly one of `result` or
`error`:

```json
{"jsonrpc":"2.0","id":"1","result":{}}
{"jsonrpc":"2.0","id":"1","error":{"code":-32602,"message":"invalid params","data":{}}}
```

The core accepts at most 8 MiB per response line. Responses can arrive in any
order, but IDs must be unique. Unknown or duplicate response IDs are diagnostics.
EOF, malformed JSON, an oversized line, or an invalid envelope terminates all
pending calls. Because byte arrays are base64-encoded, the core derives a
smaller safe output ceiling from that line bound and uses the minimum of it,
the adapter's advertised `max_output_bytes`, and the operator's `--max-output`.

## Methods

### `handshake`

Request params:

```json
{"protocol_version":"1"}
```

Result:

```json
{
  "capabilities": {
    "protocol_version":"1",
    "transport_kind":"vendor-c2",
    "interactive":false,
    "tty":false,
    "reliable_exit_status":true,
    "separate_stderr":true,
    "async_tasks":true,
    "cancel":true,
    "max_command_bytes":65536,
    "max_output_bytes":4194304,
    "upload":false,
    "download":false
  }
}
```

`async_tasks` must be true. The core does not call upload/download in the MVP,
even if advertised.

### `open_session`

Request and result:

```json
{"options":{"target":"agent-17"}}
{"session_id":"remote-session-9"}
```

Options are adapter-specific non-secret strings configured when the subprocess
starts. The returned session ID must be non-empty.

### `exec`

Request:

```json
{
  "session_id":"remote-session-9",
  "probe_id":"context.current",
  "variant_id":"proc-posix",
  "command":"sh -c 'printf ...' lpeco",
  "timeout_ms":10000,
  "max_output":524288
}
```

Result:

```json
{"task_id":"task-42"}
```

`command` is rendered centrally from a fixed probe script and separately quoted
arguments. Execute that exact string once through the approved target shell;
do not concatenate target data, wrap it in a second interpolation layer, or
silently retry it. Enforce both negotiated limits.

### `poll`

Request:

```json
{"session_id":"remote-session-9","task_id":"task-42"}
```

Pending result:

```json
{"state":"pending"}
```

Completed result (`stdout` and `stderr` are base64 because they are JSON-encoded
byte arrays):

```json
{
  "state":"complete",
  "result":{
    "stdout":"Zml4dHVyZSBjb21wbGV0ZQo=",
    "stderr":"",
    "exit_code":0,
    "status":"complete",
    "merged_output":false,
    "truncated":false,
    "started_at":"2026-10-12T00:00:00Z",
    "finished_at":"2026-10-12T00:00:01Z"
  }
}
```

Other terminal states are `failed` with an `error` string and `cancelled`.
Probe statuses are `complete`, `partial`, `unavailable`, `timeout`, `truncated`,
and `parse_error`. Set `merged_output=true` when stdout and stderr cannot be
separated. If output was clipped, set both `truncated=true` and status
`truncated`.

### `cancel`

Request and result:

```json
{"session_id":"remote-session-9","task_id":"task-42"}
{"cancelled":true,"already_complete":false}
```

The core sends this after cancellation or timeout only when `cancel=true` was
advertised. Cancellation must be idempotent.

### `close_session`

Request and result:

```json
{"session_id":"remote-session-9"}
{"closed":true}
```

Release remote task/session resources without changing the target beyond the
already completed read-only commands. The core bounds shutdown; if the adapter
does not answer before the close context expires, the subprocess is terminated.

### Reserved methods

`upload` and `download` names are reserved for a future protocol revision. A
version-1 adapter should return JSON-RPC “method not found”; LPECO core never
invokes them.

## Complete example transcript

Each arrow below represents one JSONL record. Whitespace is added only for
readability.

```text
-> {"jsonrpc":"2.0","id":"1","method":"handshake","params":{"protocol_version":"1"}}
<- {"jsonrpc":"2.0","id":"1","result":{"capabilities":{"protocol_version":"1","transport_kind":"example-c2","interactive":false,"tty":false,"reliable_exit_status":true,"separate_stderr":true,"async_tasks":true,"cancel":true,"max_command_bytes":65536,"max_output_bytes":4194304,"upload":false,"download":false}}}
-> {"jsonrpc":"2.0","id":"2","method":"open_session","params":{"options":{"target":"agent-17"}}}
<- {"jsonrpc":"2.0","id":"2","result":{"session_id":"remote-session-9"}}
-> {"jsonrpc":"2.0","id":"3","method":"exec","params":{"session_id":"remote-session-9","probe_id":"context.current","variant_id":"proc-posix","command":"sh -c 'id' lpeco","timeout_ms":10000,"max_output":524288}}
<- {"jsonrpc":"2.0","id":"3","result":{"task_id":"task-42"}}
-> {"jsonrpc":"2.0","id":"4","method":"poll","params":{"session_id":"remote-session-9","task_id":"task-42"}}
<- {"jsonrpc":"2.0","id":"4","result":{"state":"pending"}}
-> {"jsonrpc":"2.0","id":"5","method":"poll","params":{"session_id":"remote-session-9","task_id":"task-42"}}
<- {"jsonrpc":"2.0","id":"5","result":{"state":"complete","result":{"stdout":"dWlkPTEwMDAobHBlY28pCg==","exit_code":0,"status":"complete","merged_output":false,"truncated":false,"started_at":"2026-10-12T00:00:00Z","finished_at":"2026-10-12T00:00:01Z"}}}
-> {"jsonrpc":"2.0","id":"6","method":"close_session","params":{"session_id":"remote-session-9"}}
<- {"jsonrpc":"2.0","id":"6","result":{"closed":true}}
```

## Raw shell framing

Raw listener and stdio bridge transports do not use JSONL. For a random hex
nonce `N`, LPECO writes a command that emits these control-delimited records:

```text
0x1e LPECO:N:START 0x1f "\n"
...merged command output...
0x1e LPECO:N:END:<decimal-exit-code> 0x1f "\n"
```

The parser tolerates prompts, command echo, banner noise, CRLF, and arbitrary
read boundaries. It rejects malformed exits and never reports complete without
both matching markers. Only one raw probe runs at a time.
