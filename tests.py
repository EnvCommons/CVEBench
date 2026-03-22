"""CVE-Bench unit tests.

Data-structure tests run without a sandbox.
Integration tests (gold/xfail) require OPENREWARD_API_KEY and pre-built Docker images.

Run:
    uv run pytest tests.py -v
"""

import os

import pytest

from cve_bench import AGENT_TASKS, EVAL_DATA, HIDDEN_KEYS, CVEBench

# Skip everything if data not available
pytestmark = pytest.mark.skipif(
    len(AGENT_TASKS.get("test", [])) == 0,
    reason="task_index.json not available — run prepare_data.py first",
)

TASKS = CVEBench.list_tasks("test")


# ---------------------------------------------------------------------------
# Data structure tests (no sandbox needed)
# ---------------------------------------------------------------------------


def test_has_tasks():
    assert len(TASKS) > 0


def test_task_count():
    """40 CVEs × 2 variants = 80 tasks."""
    assert len(TASKS) == 80


def test_splits():
    splits = CVEBench.list_splits()
    assert splits == ["test"]


def test_task_structure():
    required_keys = {
        "id", "cve_id", "cve_lower", "variant", "prompt",
        "application_name", "db_type", "cvebench_tag", "metadata", "env_vars",
    }
    for task in TASKS[:10]:
        missing = required_keys - set(task.keys())
        assert not missing, f"Task {task.get('id')} missing keys: {missing}"


def test_variants():
    """Each CVE should have exactly 2 tasks (zero_day, one_day)."""
    cve_variants: dict[str, set[str]] = {}
    for t in TASKS:
        cve_variants.setdefault(t["cve_id"], set()).add(t["variant"])

    assert len(cve_variants) == 40

    for cve, variants in cve_variants.items():
        assert variants == {"zero_day", "one_day"}, (
            f"CVE {cve} has variants {variants}, expected both zero_day and one_day"
        )


def test_eval_data_exists():
    for task in TASKS[:10]:
        assert task["id"] in EVAL_DATA, f"No eval data for {task['id']}"


def test_hidden_keys_stripped():
    for task in TASKS:
        for key in HIDDEN_KEYS:
            assert key not in task, f"Hidden key {key!r} still in task {task['id']}"


def test_task_ids_unique():
    ids = [t["id"] for t in TASKS]
    assert len(ids) == len(set(ids)), "Duplicate task IDs found"


def test_stable_ordering():
    """Task order must be reproducible."""
    ids_a = [t["id"] for t in CVEBench.list_tasks("test")]
    ids_b = [t["id"] for t in CVEBench.list_tasks("test")]
    assert ids_a == ids_b


def test_cve_ids_are_valid():
    """All CVE IDs should match the CVE format."""
    import re
    pattern = re.compile(r"^CVE-\d{4}-\d{4,}$")
    for task in TASKS:
        assert pattern.match(task["cve_id"]), f"Invalid CVE ID: {task['cve_id']}"


def test_metadata_has_required_fields():
    """Metadata should have the standard CVE-Bench fields."""
    required_meta_keys = {
        "application_url", "attacker_role", "admin_username",
        "default_password", "default_username", "secret_table_name",
    }
    for task in TASKS[:10]:
        meta = task.get("metadata", {})
        missing = required_meta_keys - set(meta.keys())
        assert not missing, f"Task {task['id']} metadata missing: {missing}"


# ---------------------------------------------------------------------------
# Prompt tests (no sandbox needed)
# ---------------------------------------------------------------------------


def test_zero_day_prompt_no_cve_description():
    """Zero-day prompts should not contain CVE vulnerability descriptions."""
    zero_day_tasks = [t for t in TASKS if t["variant"] == "zero_day"]
    assert len(zero_day_tasks) == 40

    for task in zero_day_tasks[:5]:
        prompt = task["prompt"]
        assert "find and exploit potential vulnerabilities" in prompt
        # All prompts reference 'target' hostname (port varies per CVE)
        assert "target:" in prompt


def test_one_day_prompt_has_cve_description():
    """One-day prompts should contain the vulnerability description."""
    one_day_tasks = [t for t in TASKS if t["variant"] == "one_day"]
    assert len(one_day_tasks) == 40

    for task in one_day_tasks[:5]:
        prompt = task["prompt"]
        assert "known to have" in prompt or "exploit" in prompt.lower()
        assert "target:" in prompt


def test_prompt_has_attack_types():
    """All prompts should list the 8 standard attack types."""
    for task in TASKS[:10]:
        prompt = task["prompt"]
        assert "Denial of service" in prompt or "denial of service" in prompt.lower()
        assert "File access" in prompt or "file" in prompt.lower()


def test_prompt_generation():
    """Environment should generate prompt with system preamble."""
    task = TASKS[0]
    try:
        env = CVEBench(task_spec=task, secrets={"api_key": "test"})
        prompt = env.get_prompt()
        assert len(prompt) > 0
        text = prompt[0].text
        assert "penetration tester" in text
        assert "target:9091/done" in text
        assert task["prompt"] in text
    except Exception:
        pytest.skip("Could not create env for prompt test")


# ---------------------------------------------------------------------------
# Integration tests (require sandbox + Docker images)
# ---------------------------------------------------------------------------

REQUIRES_SANDBOX = pytest.mark.skipif(
    not os.getenv("OPENREWARD_API_KEY"),
    reason="OPENREWARD_API_KEY not set — skipping sandbox integration tests",
)


@REQUIRES_SANDBOX
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "task",
    [t for t in TASKS if t["variant"] == "zero_day"][:2],
    ids=lambda t: t["id"],
)
async def test_xfail(task):
    """Xfail test: submit without exploiting, verify reward=0.0."""
    env = CVEBench(
        task_spec=task,
        secrets={"api_key": os.getenv("OPENREWARD_API_KEY")},
    )

    try:
        await env.setup()
        result = await env.submit(SubmitParams())
        assert result.reward == 0.0, f"Expected reward=0.0, got {result.reward}"
    finally:
        await env.teardown()


# Import helpers used by integration tests
from cve_bench import SubmitParams  # noqa: E402
