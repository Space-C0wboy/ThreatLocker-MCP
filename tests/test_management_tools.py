"""Unit tests for the hand-written application / policy / action-log management tools.

Everything is mocked with pytest-httpx; no live API calls. The tests focus on
request-body construction, the dry-run / confirm / org safety rails, SHA256
batching, and the action-log projection + aggregation helpers.
"""

from __future__ import annotations

import json
import os
import re

import pytest

os.environ.setdefault("THREATLOCKER_API_KEY", "test-key")
os.environ.setdefault("THREATLOCKER_ORG_ID", "00000000-0000-0000-0000-000000000000")
os.environ.setdefault("THREATLOCKER_BASE_URL", "https://api.example.test")

from fastmcp import FastMCP  # noqa: E402

from threatlocker_mcp import client as client_module  # noqa: E402
from threatlocker_mcp import config as config_module  # noqa: E402
from threatlocker_mcp import management_models as mm  # noqa: E402
from threatlocker_mcp import write_safety  # noqa: E402
from threatlocker_mcp.client import ThreatLockerClient  # noqa: E402
from threatlocker_mcp.config import Config  # noqa: E402
from threatlocker_mcp.tools import (  # noqa: E402
    action_log_analytics,
    application_management,
    policy_management,
)

BASE = "https://api.example.test"
DEFAULT_ORG = "11111111-1111-1111-1111-111111111111"
OTHER_ORG = "22222222-2222-2222-2222-222222222222"
APP_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
POLICY_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
GROUP_ID = "33333333-3333-3333-3333-333333333333"
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> Config:
    return Config(
        api_key="test-key",
        default_org_id=DEFAULT_ORG,
        base_url=BASE,
        timeout=5.0,
        log_level="WARNING",
        http_host="127.0.0.1",
        http_port=8765,
    )


@pytest.fixture
async def tools(httpx_mock, monkeypatch, config, tmp_path):
    """Inject a mocked client + config and return a helper that runs a tool by name."""
    monkeypatch.setattr(config_module, "_config", config)
    monkeypatch.setenv(write_safety.AUDIT_LOG_ENV, str(tmp_path / "audit.jsonl"))
    test_client = ThreatLockerClient(config)
    await test_client.connect()
    monkeypatch.setattr(client_module, "_client", test_client)

    mcp = FastMCP("test")
    application_management.register(mcp)
    policy_management.register(mcp)
    action_log_analytics.register(mcp)

    async def run(tool_name: str, /, **args):
        tool = await mcp.get_tool(tool_name)
        result = await tool.run(args)
        return result.structured_content

    run.audit_path = tmp_path / "audit.jsonl"  # type: ignore[attr-defined]
    yield run
    await test_client.close()


def sent_json(request) -> dict | list:
    return json.loads(request.content)


def audit_lines(run) -> list[dict]:
    path = run.audit_path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# ---------------------------------------------------------------------------
# management_models — rule conditions, enums, helpers
# ---------------------------------------------------------------------------


def test_rule_combines_path_process_created_by_and_cert():
    rule = mm.ApplicationFileRule(
        full_path="C:\\Apps\\launcher.exe",
        process_path="C:\\Windows\\explorer.exe",
        created_by="C:\\Installers\\setup.exe",
        cert="CN=Vendor",
        notes="combo",
    )
    dto = rule.to_application_file_dto(os_type=1, application_id=APP_ID, application_name="App")
    assert dto == {
        "osType": 1,
        "notes": "combo",
        "applicationId": APP_ID,
        "applicationName": "App",
        "fullPath": "C:\\Apps\\launcher.exe",
        "processPath": "C:\\Windows\\explorer.exe",
        "installedBy": "C:\\Installers\\setup.exe",
        "cert": "CN=Vendor",
    }
    assert "isHashOnly" not in dto


def test_sha256_rule_is_hash_only_and_lowercased():
    rule = mm.ApplicationFileRule(sha256=SHA_A.upper(), notes="n")
    dto = rule.to_application_file_dto(os_type=1, update_status=1)
    assert dto == {"osType": 1, "notes": "n", "hash": SHA_A, "isHashOnly": True, "updateStatus": 1}


def test_tl_hash_rule_is_hash_only():
    dto = mm.ApplicationFileRule(hash="deadbeef").to_application_file_dto(os_type=2)
    assert dto["hash"] == "deadbeef" and dto["isHashOnly"] is True and dto["osType"] == 2


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # no condition
        {"hash": "x", "full_path": "C:\\a.exe"},  # hash not standalone
        {"sha256": SHA_A, "cert": "CN=x"},  # sha256 not standalone
        {"hash": "x", "sha256": SHA_A},  # both hashes
        {"process_path": "C:\\p.exe"},  # process alone
        {"created_by": "C:\\c.exe"},  # created-by alone
        {"process_path": "C:\\p.exe", "created_by": "C:\\c.exe"},  # both without anchor
        {"sha256": "not-hex"},
    ],
)
def test_rule_rejects_invalid_combinations(kwargs):
    with pytest.raises(ValueError):
        mm.ApplicationFileRule(**kwargs)


def test_resolve_applies_to_variants():
    assert mm.resolve_applies_to("organization", OTHER_ORG) == OTHER_ORG
    assert mm.resolve_applies_to("Entire Organization", OTHER_ORG) == OTHER_ORG
    assert mm.resolve_applies_to(GROUP_ID, OTHER_ORG) == GROUP_ID
    with pytest.raises(ValueError):
        mm.resolve_applies_to("Workstations", OTHER_ORG)


def test_resolve_enums():
    assert mm.resolve_policy_action("permit") == 1
    assert mm.resolve_policy_action("Deny") == 2
    assert mm.resolve_policy_action("Permit with Ringfencing") == 6
    assert mm.resolve_policy_action(6) == 6
    assert mm.resolve_os_type("mac") == 2
    assert mm.resolve_os_type(3) == 3
    with pytest.raises(ValueError):
        mm.resolve_policy_action("maybe")
    with pytest.raises(ValueError):
        mm.resolve_os_type(9)


def test_normalize_sha256_list_dedupes_and_rejects():
    valid, rejected = mm.normalize_sha256_list([SHA_A, SHA_A.upper(), "zz", "", SHA_B])
    assert valid == [SHA_A, SHA_B]
    assert [r["reason"] for r in rejected] == [
        "duplicate in input",
        "not a 64-character hex SHA256",
        "empty",
    ]


def test_folder_of_and_pick_fields():
    assert mm.folder_of("C:\\Program Files\\App\\app.exe") == "C:\\Program Files\\App"
    assert mm.folder_of("/usr/bin/python3") == "/usr/bin"
    assert mm.folder_of(None) == ""
    row = {"hostName": "PC-1", "fullPath": "x", "policyName": "p"}
    assert mm.pick_fields(row, ["hostname", "policyName"]) == {
        "hostname": "PC-1",
        "policyName": "p",
    }


# ---------------------------------------------------------------------------
# write_safety
# ---------------------------------------------------------------------------


def test_require_confirmation_blocks_only_live_runs():
    write_safety.require_confirmation(True, False, "x")  # dry run: fine
    write_safety.require_confirmation(False, True, "x")  # confirmed: fine
    with pytest.raises(write_safety.WriteBlocked, match="confirm=true"):
        write_safety.require_confirmation(False, False, "Deploying")


def test_record_audit_writes_json_line_without_secrets(monkeypatch, tmp_path):
    monkeypatch.setenv(write_safety.AUDIT_LOG_ENV, str(tmp_path / "a.jsonl"))
    write_safety.record_audit(
        tool="t",
        organization_id=DEFAULT_ORG,
        method="POST",
        path="/p",
        target_id="id",
        outcome="ok",
    )
    line = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert line["tool"] == "t" and line["outcome"] == "ok" and "timestamp" in line
    assert "Authorization" not in json.dumps(line) and "test-key" not in json.dumps(line)


# ---------------------------------------------------------------------------
# application_insert
# ---------------------------------------------------------------------------


async def test_application_insert_dry_run_sends_nothing(tools, httpx_mock):
    result = await tools(
        "application_insert",
        name="ZZ-MCP-TEST",
        os_type="windows",
        description="throwaway",
        rules=[{"full_path": "C:\\Apps\\*.exe", "process_path": "C:\\Windows\\explorer.exe"}],
    )
    assert result["dry_run"] is True
    assert result["organization_id"] == DEFAULT_ORG  # falls back to the configured default only
    req = result["requests"][0]
    assert req["method"] == "POST" and req["path"].endswith("/Application/ApplicationInsert")
    assert req["json"] == {
        "name": "ZZ-MCP-TEST",
        "osType": 1,
        "description": "throwaway",
        "applicationFileUpdates": [
            {
                "osType": 1,
                "notes": application_management.DEFAULT_RULE_NOTES,
                "fullPath": "C:\\Apps\\*.exe",
                "processPath": "C:\\Windows\\explorer.exe",
                "updateStatus": 1,
            }
        ],
    }
    assert httpx_mock.get_requests() == []


async def test_application_insert_live_targets_explicit_org_and_audits(tools, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/portalapi/Application/ApplicationInsert",
        json={"applicationId": APP_ID},
        match_headers={"ManagedOrganizationId": OTHER_ORG},
    )
    result = await tools(
        "application_insert", name="ZZ-MCP-TEST", organization_id=OTHER_ORG, dry_run=False
    )
    assert result["dry_run"] is False
    assert result["results"][0]["response"] == {"applicationId": APP_ID}
    assert sent_json(httpx_mock.get_request()) == {
        "name": "ZZ-MCP-TEST",
        "osType": 1,
        "description": "",
    }
    [line] = audit_lines(tools)
    assert line["tool"] == "application_insert"
    assert line["organization_id"] == OTHER_ORG
    assert line["outcome"] == "ok"
    assert "test-key" not in json.dumps(line)


# ---------------------------------------------------------------------------
# application_update
# ---------------------------------------------------------------------------

APP_GET_URL = re.compile(rf"{re.escape(BASE)}/portalapi/Application/ApplicationGetById\?.*")
RULES_URL = re.compile(
    rf"{re.escape(BASE)}/portalapi/ApplicationFile/ApplicationFileGetByApplicationId\?.*"
)


def _app_payload(**overrides):
    base = {
        "applicationId": APP_ID,
        "name": "ZZ-MCP-TEST",
        "description": "keep me",
        "osType": 1,
        "organizationId": OTHER_ORG,
        "applicationFiles": [],
    }
    base.update(overrides)
    return base


async def test_application_update_preserves_description_and_adds_rule(tools, httpx_mock):
    httpx_mock.add_response(method="GET", url=APP_GET_URL, json=_app_payload())
    httpx_mock.add_response(
        method="PUT", url=f"{BASE}/portalapi/Application/ApplicationUpdateById", json={}
    )
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/portalapi/ApplicationFile/ApplicationFileInsert", json={}
    )
    result = await tools(
        "application_update",
        application_id=APP_ID,
        name="ZZ-MCP-TEST-2",
        add_rules=[{"sha256": SHA_A, "notes": "launcher"}],
        organization_id=OTHER_ORG,
        dry_run=False,
    )
    assert result["request_count"] == 2
    put = httpx_mock.get_request(method="PUT")
    assert sent_json(put) == {
        "applicationId": APP_ID,
        "name": "ZZ-MCP-TEST-2",
        "description": "keep me",  # carried over from the GET, not wiped
        "osType": 1,
    }
    post = httpx_mock.get_request(method="POST")
    assert sent_json(post) == {
        "osType": 1,
        "notes": "launcher",
        "applicationId": APP_ID,
        "applicationName": "ZZ-MCP-TEST-2",
        "hash": SHA_A,
        "isHashOnly": True,
    }


async def test_application_update_remove_requires_confirm(tools, httpx_mock):
    with pytest.raises(write_safety.WriteBlocked, match="confirm=true"):
        await tools(
            "application_update",
            application_id=APP_ID,
            remove_rule_ids=[42],
            dry_run=False,
            confirm=False,
        )
    assert httpx_mock.get_requests() == []


async def test_application_update_remove_rule_includes_rule_conditions(tools, httpx_mock):
    httpx_mock.add_response(method="GET", url=APP_GET_URL, json=_app_payload())
    httpx_mock.add_response(
        method="GET",
        url=RULES_URL,
        json=[
            {"applicationFileId": 42, "fullPath": "C:\\old\\*.exe", "cert": "CN=Old", "hash": ""},
            {"applicationFileId": 43, "hash": SHA_B, "isHashOnly": True},
        ],
    )
    result = await tools(
        "application_update",
        application_id=APP_ID,
        remove_rule_ids=[42],
        dry_run=True,
        confirm=True,
    )
    assert result["dry_run"] is True
    [req] = result["requests"]
    assert req["path"].endswith("/ApplicationFile/ApplicationFileDeleteById")
    assert req["json"] == {
        "applicationFileId": 42,
        "applicationId": APP_ID,
        "applicationName": "ZZ-MCP-TEST",
        "osType": 1,
        "fullPath": "C:\\old\\*.exe",
        "cert": "CN=Old",
    }
    # Dry run performed only the two reads, no POST.
    assert all(r.method == "GET" for r in httpx_mock.get_requests())


async def test_application_update_unknown_rule_id_blocks(tools, httpx_mock):
    httpx_mock.add_response(method="GET", url=APP_GET_URL, json=_app_payload())
    httpx_mock.add_response(method="GET", url=RULES_URL, json=[{"applicationFileId": 1}])
    with pytest.raises(write_safety.WriteBlocked, match=r"\[99\]"):
        await tools("application_update", application_id=APP_ID, remove_rule_ids=[99], confirm=True)


# ---------------------------------------------------------------------------
# application_add_sha256_bulk
# ---------------------------------------------------------------------------


async def test_bulk_sha256_dry_run_plans_batches_and_skips_existing(tools, httpx_mock):
    httpx_mock.add_response(method="GET", url=APP_GET_URL, json=_app_payload())
    httpx_mock.add_response(method="GET", url=RULES_URL, json=[{"hash": SHA_C, "isHashOnly": True}])
    result = await tools(
        "application_add_sha256_bulk",
        application_id=APP_ID,
        sha256_list=[SHA_A, SHA_B, SHA_C, SHA_A, "bogus"],
        batch_size=1,
    )
    assert result["dry_run"] is True
    assert result["input_count"] == 5
    assert result["already_present_count"] == 1
    assert result["to_add_count"] == 2
    assert result["batch_count"] == 2
    assert [r["reason"] for r in result["rejected"]] == [
        "duplicate in input",
        "not a 64-character hex SHA256",
    ]
    assert len(result["requests"]) == 2
    assert result["requests"][0]["json"]["hash"] == SHA_A
    assert result["requests"][0]["json"]["isHashOnly"] is True
    assert all(r.method == "GET" for r in httpx_mock.get_requests())


async def test_bulk_sha256_live_counts_added_and_failed(tools, httpx_mock):
    httpx_mock.add_response(method="GET", url=APP_GET_URL, json=_app_payload())
    insert_url = f"{BASE}/portalapi/ApplicationFile/ApplicationFileInsert"
    # Three hashes, three inserts: two succeed, one fails with a non-retryable 417.
    httpx_mock.add_response(method="POST", url=insert_url, json={"ok": 1})
    httpx_mock.add_response(
        method="POST", url=insert_url, status_code=417, json={"message": "duplicate rule"}
    )
    httpx_mock.add_response(method="POST", url=insert_url, json={"ok": 3})
    result = await tools(
        "application_add_sha256_bulk",
        application_id=APP_ID,
        sha256_list=[SHA_A, SHA_B, SHA_C],
        skip_existing=False,
        batch_size=2,
        dry_run=False,
    )
    assert result["dry_run"] is False
    assert result["to_add_count"] == 3
    assert result["added_count"] + result["failed_count"] == 3
    assert result["failed_count"] == 1
    assert "417" in result["failed"][0]["error"]
    posts = httpx_mock.get_requests(method="POST")
    assert len(posts) == 3
    assert {sent_json(p)["hash"] for p in posts} == {SHA_A, SHA_B, SHA_C}
    assert all(sent_json(p)["applicationId"] == APP_ID for p in posts)
    lines = audit_lines(tools)
    assert len(lines) == 3
    assert sorted(line["outcome"] for line in lines) == ["error", "ok", "ok"]


# ---------------------------------------------------------------------------
# application_delete
# ---------------------------------------------------------------------------


async def test_application_delete_requires_confirm_and_builds_body(tools, httpx_mock):
    with pytest.raises(write_safety.WriteBlocked):
        await tools("application_delete", application_id=APP_ID, dry_run=False)
    assert httpx_mock.get_requests() == []

    httpx_mock.add_response(method="GET", url=APP_GET_URL, json=_app_payload())
    httpx_mock.add_response(
        method="POST", url=f"{BASE}/portalapi/Application/ApplicationUpdateForDelete", json={}
    )
    await tools(
        "application_delete",
        application_id=APP_ID,
        organization_id=OTHER_ORG,
        dry_run=False,
        confirm=True,
    )
    assert sent_json(httpx_mock.get_request(method="POST")) == {
        "applications": [
            {
                "applicationId": APP_ID,
                "name": "ZZ-MCP-TEST",
                "organizationId": OTHER_ORG,
                "osType": 1,
            }
        ]
    }


async def test_application_delete_force_uses_confirm_endpoint(tools, httpx_mock):
    httpx_mock.add_response(method="GET", url=APP_GET_URL, json=_app_payload())
    result = await tools(
        "application_delete", application_id=APP_ID, force_with_policies=True, confirm=True
    )
    assert result["requests"][0]["path"].endswith("/Application/ApplicationConfirmUpdateForDelete")


# ---------------------------------------------------------------------------
# policy_insert
# ---------------------------------------------------------------------------


async def test_policy_insert_applies_to_variants(tools, httpx_mock):
    org_level = await tools(
        "policy_insert",
        name="ZZ-MCP-TEST policy",
        application_ids=[APP_ID],
        applies_to="organization",
        organization_id=OTHER_ORG,
    )
    assert org_level["requests"][0]["json"]["computerGroupId"] == OTHER_ORG

    group_level = await tools(
        "policy_insert", name="p", application_ids=[APP_ID], applies_to=GROUP_ID
    )
    assert group_level["requests"][0]["json"]["computerGroupId"] == GROUP_ID
    assert httpx_mock.get_requests() == []


async def test_policy_insert_body_shape(tools, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/portalapi/Policy/PolicyInsert",
        json={"result": {"policyId": POLICY_ID}},
        match_headers={"ManagedOrganizationId": OTHER_ORG},
    )
    await tools(
        "policy_insert",
        name="Deny launchers",
        description="d",
        application_ids=[APP_ID],
        applies_to=GROUP_ID,
        action="deny",
        is_enabled=False,
        add_to_top=True,
        extra_fields={"monitorMode": 1},
        organization_id=OTHER_ORG,
        dry_run=False,
    )
    assert sent_json(httpx_mock.get_request()) == {
        "name": "Deny launchers",
        "description": "d",
        "osType": 1,
        "policyActionId": 2,
        "applicationIdList": [APP_ID],
        "computerGroupId": GROUP_ID,
        "logAction": True,
        "isEnabled": False,
        "orderBefore": True,
        "allUserGroups": True,
        "monitorMode": 1,
    }


async def test_policy_insert_rejects_unlogged_deny(tools):
    with pytest.raises(write_safety.WriteBlocked, match="log_action"):
        await tools(
            "policy_insert",
            name="p",
            application_ids=[APP_ID],
            applies_to=GROUP_ID,
            action="deny",
            log_action=False,
        )


# ---------------------------------------------------------------------------
# policy_update / policy_set_order / policy_delete
# ---------------------------------------------------------------------------

POLICY_GET_URL = re.compile(rf"{re.escape(BASE)}/portalapi/Policy/PolicyGetById\?.*")


def _policy_payload(**overrides):
    base = {
        "policyId": POLICY_ID,
        "name": "ZZ-MCP-TEST policy",
        "description": "d",
        "osType": 1,
        "policyActionId": 1,
        "appliesToId": GROUP_ID,  # alias for computerGroupId
        "applications": [{"applicationId": APP_ID, "name": "ZZ-MCP-TEST"}],
        "logAction": True,
        "isEnabled": True,
        "orderBy": 100_010,
        "allUserGroups": True,
        "organizationId": OTHER_ORG,
        "ringfencingOptions": {"restrictNetworkAccess": False},
        "someUnrelatedReadOnlyField": "ignored",
    }
    base.update(overrides)
    return base


def test_build_policy_update_body_carries_fields_and_applies_changes():
    body, carried = policy_management.build_policy_update_body(
        _policy_payload(), {"isEnabled": False, "name": "renamed", "orderBy": None}
    )
    assert body["computerGroupId"] == GROUP_ID
    assert body["applicationIdList"] == [APP_ID]
    assert body["isEnabled"] is False
    assert body["name"] == "renamed"
    assert body["orderBy"] == 100_010  # None change leaves the carried value
    assert body["ringfencingOptions"] == {"restrictNetworkAccess": False}
    assert "someUnrelatedReadOnlyField" not in body
    assert "computerGroupId" in carried and "applicationIdList" in carried


async def test_policy_update_read_modify_write(tools, httpx_mock):
    httpx_mock.add_response(method="GET", url=POLICY_GET_URL, json=_policy_payload())
    httpx_mock.add_response(method="PUT", url=f"{BASE}/portalapi/Policy/PolicyUpdateById", json={})
    result = await tools(
        "policy_update",
        policy_id=POLICY_ID,
        is_enabled=False,
        applies_to="organization",
        application_ids=[APP_ID, "cccccccc-cccc-cccc-cccc-cccccccccccc"],
        action="permit_with_ringfencing",
        organization_id=OTHER_ORG,
        dry_run=False,
    )
    sent = sent_json(httpx_mock.get_request(method="PUT"))
    assert sent["policyId"] == POLICY_ID
    assert sent["isEnabled"] is False
    assert sent["computerGroupId"] == OTHER_ORG
    assert sent["policyActionId"] == 6
    assert sent["applicationIdList"] == [APP_ID, "cccccccc-cccc-cccc-cccc-cccccccccccc"]
    assert sent["name"] == "ZZ-MCP-TEST policy" and sent["logAction"] is True
    assert any("carried over" in n for n in result["notes"])


async def test_policy_update_requires_a_change(tools, httpx_mock):
    with pytest.raises(write_safety.WriteBlocked, match="Nothing to do"):
        await tools("policy_update", policy_id=POLICY_ID)
    assert httpx_mock.get_requests() == []


async def test_policy_set_order_updates_each_policy(tools, httpx_mock):
    other = "dddddddd-dddd-dddd-dddd-dddddddddddd"
    httpx_mock.add_response(method="GET", url=POLICY_GET_URL, json=_policy_payload())
    httpx_mock.add_response(
        method="GET", url=POLICY_GET_URL, json=_policy_payload(policyId=other, orderBy=5)
    )
    put_url = f"{BASE}/portalapi/Policy/PolicyUpdateById"
    httpx_mock.add_response(method="PUT", url=put_url, json={})
    httpx_mock.add_response(method="PUT", url=put_url, json={})
    result = await tools(
        "policy_set_order",
        orders=[{"policy_id": POLICY_ID, "order_by": 1}, {"policy_id": other, "order_by": 2}],
        dry_run=False,
    )
    assert result["request_count"] == 2
    puts = [sent_json(r) for r in httpx_mock.get_requests(method="PUT")]
    assert [(p["policyId"], p["orderBy"]) for p in puts] == [(POLICY_ID, 1), (other, 2)]
    assert all(p["name"] == "ZZ-MCP-TEST policy" for p in puts)  # everything else preserved


async def test_policy_set_order_rejects_negative():
    with pytest.raises(ValueError):
        policy_management.PolicyOrderChange(policy_id=POLICY_ID, order_by=-1)


async def test_policy_delete_confirm_and_body(tools, httpx_mock):
    with pytest.raises(write_safety.WriteBlocked):
        await tools("policy_delete", policy_ids=[POLICY_ID], dry_run=False)

    httpx_mock.add_response(method="GET", url=POLICY_GET_URL, json=_policy_payload())
    httpx_mock.add_response(
        method="PUT", url=f"{BASE}/portalapi/Policy/PolicyUpdateForDeleteByIds", json={}
    )
    await tools(
        "policy_delete",
        policy_ids=[POLICY_ID],
        organization_id=OTHER_ORG,
        dry_run=False,
        confirm=True,
    )
    assert sent_json(httpx_mock.get_request(method="PUT")) == [
        {
            "policyId": POLICY_ID,
            "name": "ZZ-MCP-TEST policy",
            "organizationId": OTHER_ORG,
            "osType": 1,
        }
    ]


# ---------------------------------------------------------------------------
# policies_deploy
# ---------------------------------------------------------------------------


async def test_policies_deploy_dry_run_then_confirm(tools, httpx_mock):
    dry = await tools("policies_deploy", organization_id=OTHER_ORG)
    assert dry["dry_run"] is True
    assert dry["requests"][0]["path"].endswith("/DeployPolicyQueue/DeployPolicies")
    assert "json" not in dry["requests"][0]

    with pytest.raises(write_safety.WriteBlocked):
        await tools("policies_deploy", organization_id=OTHER_ORG, dry_run=False)
    assert httpx_mock.get_requests() == []

    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/portalapi/DeployPolicyQueue/DeployPolicies",
        json={},
        match_headers={"ManagedOrganizationId": OTHER_ORG},
    )
    live = await tools("policies_deploy", organization_id=OTHER_ORG, dry_run=False, confirm=True)
    assert live["dry_run"] is False
    assert audit_lines(tools)[0]["tool"] == "policies_deploy"


async def test_policies_deploy_single_computer(tools, httpx_mock):
    with pytest.raises(write_safety.WriteBlocked, match="computer_name"):
        await tools("policies_deploy", computer_id="x")
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/portalapi/DeployPolicyQueue/DeployPoliciesForComputer?computerId=c1&computerName=PC-1",
        json={},
    )
    await tools(
        "policies_deploy", computer_id="c1", computer_name="PC-1", dry_run=False, confirm=True
    )
    assert httpx_mock.get_request() is not None


# ---------------------------------------------------------------------------
# policy_list
# ---------------------------------------------------------------------------


async def test_policy_list_default_body_and_compact_projection(tools, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/portalapi/Policy/PolicyGetByParameters",
        json=[
            {
                "policyId": POLICY_ID,
                "name": "Allow ZZ",
                "orderBy": 100_010,
                "policyActionId": 1,
                "isEnabled": True,
                "appliesToId": OTHER_ORG,
                "lastMatch": "2026-11-01T00:00:00Z",
                "totalRows": 1,
                "noise": "x",
            }
        ],
    )
    result = await tools("policy_list", organization_id=OTHER_ORG, include_inactive=True)
    assert sent_json(httpx_mock.get_request()) == {
        "computerGroupId": mm.ALL_ZEROS_GUID,
        "filter": "",
        "pageNumber": 1,
        "pageSize": 50,
        "activeOnly": False,
        "osType": 1,
        "searchText": "",
        "showAllPolicies": False,
    }
    assert result["total"] == 1
    [row] = result["policies"]
    assert row["action"] == "permit"
    assert row["policyLevel"] == "organization"
    assert row["lastMatch"] == "2026-11-01T00:00:00Z"
    assert "noise" not in row


async def test_policy_list_by_application_uses_view_endpoint(tools, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=f"{BASE}/portalapi/Policy/PolicyGetForViewPoliciesByApplicationId",
        json=[],
    )
    result = await tools(
        "policy_list", application_id=APP_ID, applies_to=GROUP_ID, organization_id=OTHER_ORG
    )
    assert sent_json(httpx_mock.get_request()) == {
        "applicationId": APP_ID,
        "organizationId": OTHER_ORG,
        "pageNumber": 1,
        "pageSize": 50,
        "includeDenies": True,
        "appliesToId": GROUP_ID,
    }
    assert result["returned"] == 0


# ---------------------------------------------------------------------------
# action_log_search
# ---------------------------------------------------------------------------

AL_URL = f"{BASE}/portalapi/ActionLog/ActionLogGetByParametersV2"
AL_HEADERS = {"totalItems": "2345", "totalPages": "24", "currentPage": "1", "itemsPerPage": "100"}


async def test_action_log_search_paging_and_fields(tools, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=AL_URL,
        headers=AL_HEADERS,
        json=[
            {"dateTime": "t1", "hostname": "PC-1", "fullPath": "C:\\a\\b.exe", "extra": 1},
            {"dateTime": "t2", "hostname": "PC-2", "fullPath": "C:\\a\\c.exe", "extra": 2},
        ],
    )
    result = await tools(
        "action_log_search",
        start_date="2026-11-01T00:00:00Z",
        end_date="2026-11-08T00:00:00Z",
        hostname="PC-*",
        action_id=2,
        page_number=1,
        page_size=100,
        fields=["dateTime", "HOSTNAME"],
    )
    req = httpx_mock.get_request()
    assert req.headers["usenewsearch"] == "true"
    sent = sent_json(req)
    assert sent["pageNumber"] == 1 and sent["pageSize"] == 100
    assert sent["showTotalCount"] is True
    assert sent["paramsFieldsDto"] == []
    assert sent["hostname"] == "PC-*" and sent["actionId"] == 2
    assert sent["startDate"] == "2026-11-01T00:00:00Z"
    assert "groupBys" not in sent
    assert result["paging"] == {
        "page_number": 1,
        "page_size": 100,
        "returned": 2,
        "total_items": 2345,
        "total_pages": 24,
        "current_page": 1,
        "items_per_page": 100,
    }
    assert result["rows"] == [
        {"dateTime": "t1", "HOSTNAME": "PC-1"},
        {"dateTime": "t2", "HOSTNAME": "PC-2"},
    ]


async def test_action_log_search_server_side_aggregate(tools, httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url=AL_URL,
        headers=AL_HEADERS,
        json=[
            {"policyName": "Default Deny", "groupByCount": 120},
            {"policyName": "Allow Chrome", "groupByCount": 400},
        ],
    )
    result = await tools(
        "action_log_search",
        start_date="2026-11-01T00:00:00Z",
        end_date="2026-11-08T00:00:00Z",
        aggregate_by=["policyName"],
    )
    assert sent_json(httpx_mock.get_request())["groupBys"] == [6]
    assert result["mode"] == "server"
    assert result["groups"] == [
        {"policyName": "Allow Chrome", "count": 400},
        {"policyName": "Default Deny", "count": 120},
    ]


async def test_action_log_search_client_side_folder_aggregate(tools, httpx_mock, monkeypatch):
    monkeypatch.setattr(action_log_analytics, "CLIENT_PAGE_SIZE", 2)
    httpx_mock.add_response(
        method="POST",
        url=AL_URL,
        headers={"totalItems": "3"},
        json=[{"fullPath": "C:\\x\\a.exe"}, {"fullPath": "C:\\x\\b.exe"}],
    )
    httpx_mock.add_response(
        method="POST", url=AL_URL, headers={"totalItems": "3"}, json=[{"fullPath": "D:\\y\\c.exe"}]
    )
    result = await tools(
        "action_log_search",
        start_date="2026-11-01T00:00:00Z",
        end_date="2026-11-08T00:00:00Z",
        aggregate_by=["fullPathFolder"],
    )
    pages = [sent_json(r)["pageNumber"] for r in httpx_mock.get_requests()]
    assert pages == [1, 2]
    assert sent_json(httpx_mock.get_requests()[1])["totalRows"] == 3  # fed back for deep paging
    assert result["mode"] == "client"
    assert result["rows_scanned"] == 3 and result["truncated"] is False
    assert result["groups"] == [
        {"fullPathFolder": "C:\\x", "count": 2},
        {"fullPathFolder": "D:\\y", "count": 1},
    ]


def test_resolve_aggregates_modes():
    assert action_log_analytics.resolve_aggregates(["policyName", "hostname"], "auto") == (
        "server",
        [6, 17],
    )
    assert action_log_analytics.resolve_aggregates(["fullPathFolder"], "auto") == ("client", [])
    assert action_log_analytics.resolve_aggregates(["policyName"], "client") == ("client", [])
    with pytest.raises(ValueError, match="Unknown aggregate_by"):
        action_log_analytics.resolve_aggregates(["nope"], "auto")
    with pytest.raises(ValueError):
        action_log_analytics.resolve_aggregates(["fullPathFolder"], "server")
