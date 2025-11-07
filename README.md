# mcpguard

`mcpguard` is a lightweight security and policy middleware for Model Context Protocol (MCP) servers. It protects tool execution and resource access with configurable policies, rate limiting, authentication, and prompt-injection heuristics.

## Features

* Allow/deny policies for tools, resources, and prompts
* Token bucket rate limiting with in-memory or Redis backends
* Resource URI ACLs with glob and regex support
* Prompt-injection heuristics
* API key and bearer token authentication
* Structured audit logging with attestation stubs
* Library and sidecar proxy integration modes

## Installation

```bash
pip install -e .
# or using uv
uv pip install -e .
```

## Quickstart

1. Launch the minimal MCP server:

```bash
python examples/minimal_server.py
```

2. Run the guard proxy:

```bash
mcpguard proxy --policy examples/policy.yaml --target ws://localhost:8765
# clients connect to ws://localhost:8787/ws by default
```

3. Send a tool call (e.g., via websockets or curl for HTTP endpoints). Calls to `calculator.add` will be allowed, while `admin.echo-env` will be denied by policy.

### Example Policy

```yaml
version: 1
auth:
  mode: api_key
  allowed_keys:
    - demo-key
tools:
  allow:
    - "calculator/*"
  deny:
    - "admin/*"
resources:
  allow:
    - "file://**/*.md"
  deny:
    - "file://**/.env"
prompts:
  deny_regex:
    - "(?i)ignore.*instructions"
    - "(?i)exfiltrate"
  max_length: 4000
rate_limit:
  capacity: 30
  refill_rate_per_sec: 1.0
  backend: memory
logging:
  level: INFO
  output: stderr
attestation:
  enabled: true
  alg: sha256
```

### Library Usage

```python
from mcpguard.guard import Guard
from mcpguard.policy import load_policy

policy = load_policy("examples/policy.yaml")
guard = Guard(policy)

@guard.wrap_tool(tool_name="calculator.add")
async def calculator_add(a: int, b: int) -> int:
    return a + b
```

### Proxy CLI

```
mcpguard proxy --policy examples/policy.yaml --target ws://localhost:8765
# clients connect to ws://localhost:8787/ws by default
mcpguard check --policy examples/policy.yaml --tool calculator.add --prompt "add two numbers" --identity alice
```

### Audit Logging

Audit logs are emitted as JSON lines containing `decision="allow"` or `decision="deny"`. A blocked prompt will produce a log entry similar to:

```json
{
  "ts": "2024-01-01T00:00:00Z",
  "identity": "alice",
  "tool": "calculator.add",
  "decision": "deny",
  "reason": "PromptInjectionSuspected",
  "findings": [
    {"rule_id": "prompt_regex_0", "severity": "high", "reason": "Matched (?i)ignore.*instructions"}
  ]
}
```

## Security Model

* Policies are declarative and validated with Pydantic.
* Authentication is enforced prior to any checks.
* Rate limiting applies per identity and tool.
* Prompt heuristics guard against common injection patterns.
* Attestation stubs provide hashes for future signing integration.

### Limitations

* Proxy currently supports JSON WebSocket frames for MCP-like messages.
* Redis backend usage requires providing a DSN and running Redis.
* Prompt heuristics are pattern-based and may require tuning for your environment.

## Development

Use the provided Makefile:

```bash
make install
make lint
make typecheck
make test
```

## License

MIT License. See [LICENSE](LICENSE).
