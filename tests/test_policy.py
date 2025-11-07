import pathlib

from mcpguard.policy import Policy, load_policy


def test_load_policy(tmp_path: pathlib.Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        """
version: 1
auth:
  mode: none
tools:
  allow: ["calculator/*"]
resources:
  allow: ["file://**/*.md"]
prompts:
  deny_regex: ["(?i)ignore"]
rate_limit:
  capacity: 10
  refill_rate_per_sec: 1.0
  backend: memory
logging:
  level: INFO
attestation:
  enabled: false
        """
    )
    policy = load_policy(policy_path)
    assert isinstance(policy, Policy)
    assert policy.auth.mode == "none"
    assert policy.prompts.max_length == 4000
    assert len(policy.prompts.compiled_patterns) == 1
    assert policy.tool_allowed("calculator.add")
    assert not policy.tool_allowed("admin.echo")
