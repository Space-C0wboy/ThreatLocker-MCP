"""Hand-written input models and enums for the application / policy management tools.

These endpoints are documented in the ThreatLocker knowledge base rather than
the public Swagger document, so their request models live here instead of in
the generated ``models.py``. Field names on the wire match the KB verbatim:

- https://threatlocker.kb.help/portalapiapplication/
- https://threatlocker.kb.help/portalapiapplicationfile/
- https://threatlocker.kb.help/portalapipolicy/
- https://threatlocker.kb.help/portalapideploypolicyqueue/
- https://threatlocker.kb.help/unified-audit-portalapiactionlog/
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Enums (ThreatLocker integer codes)
# ---------------------------------------------------------------------------

OS_TYPES: dict[str, int] = {"all": 0, "windows": 1, "mac": 2, "linux": 3, "windows_xp": 5}
OS_TYPE_NAMES: dict[int, str] = {v: k for k, v in OS_TYPES.items()}

# policyActionId values from the KB policy article.
POLICY_ACTIONS: dict[str, int] = {"permit": 1, "deny": 2, "permit_with_ringfencing": 6}
POLICY_ACTION_NAMES: dict[int, str] = {v: k for k, v in POLICY_ACTIONS.items()}

# "Entire Organization" is an applies-to target whose GUID is the organization
# id itself (entityType 1 in ComputerGroupGetGroupAndComputer). Computer groups
# are entityType 2, individual computers entityType 3. All-zeros means "all
# policies" and is only meaningful as a *filter* in PolicyGetByParameters.
ALL_ZEROS_GUID = "00000000-0000-0000-0000-000000000000"
ENTIRE_ORGANIZATION = "organization"

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def is_guid(value: str | None) -> bool:
    return bool(value) and bool(_GUID_RE.match(value or ""))


def resolve_os_type(value: int | str) -> int:
    """Accept 1 / "windows" / "Windows" and return the integer code."""
    if isinstance(value, bool):  # bool is an int subclass; reject explicitly
        raise ValueError("os_type must be an integer code or a name, not a boolean")
    if isinstance(value, int):
        if value not in OS_TYPE_NAMES:
            raise ValueError(f"Unknown os_type {value}; expected one of {sorted(OS_TYPE_NAMES)}")
        return value
    key = str(value).strip().lower().replace(" ", "_")
    if key not in OS_TYPES:
        raise ValueError(f"Unknown os_type {value!r}; expected one of {sorted(OS_TYPES)}")
    return OS_TYPES[key]


def resolve_policy_action(value: int | str) -> int:
    """Accept 1 / "permit" / "Permit with Ringfencing" and return policyActionId."""
    if isinstance(value, bool):
        raise ValueError("action must be an integer code or a name, not a boolean")
    if isinstance(value, int):
        if value not in POLICY_ACTION_NAMES:
            raise ValueError(
                f"Unknown policy action {value}; expected one of {sorted(POLICY_ACTION_NAMES)}"
            )
        return value
    key = re.sub(r"[\s\-]+", "_", str(value).strip().lower())
    aliases = {
        "permit": "permit",
        "allow": "permit",
        "deny": "deny",
        "block": "deny",
        "permit_with_ringfencing": "permit_with_ringfencing",
        "ringfence": "permit_with_ringfencing",
        "ringfenced": "permit_with_ringfencing",
        "permit_ringfence": "permit_with_ringfencing",
        "permit_ringfenced": "permit_with_ringfencing",
    }
    if key not in aliases:
        raise ValueError(f"Unknown policy action {value!r}; expected one of {sorted(aliases)}")
    return POLICY_ACTIONS[aliases[key]]


def resolve_applies_to(applies_to: str, organization_id: str) -> str:
    """Translate the tool-facing ``applies_to`` value into the API's GUID.

    * ``"organization"`` (or ``"entire_organization"`` / ``"org"``) → the target
      organization's own GUID, which is how ThreatLocker represents an
      entire-organization policy.
    * any GUID → passed through (a computer group id or a computer id).
    """
    key = applies_to.strip().lower().replace(" ", "_").replace("-", "_")
    if key in {"organization", "entire_organization", "org", "entire_org"}:
        return organization_id
    if is_guid(applies_to.strip()):
        return applies_to.strip()
    raise ValueError(
        "applies_to must be 'organization' or a computer-group / computer GUID. Use "
        "computer_group_get_dropdown_by_organization_id for group GUIDs and "
        "computer_get_by_all_parameters for computer GUIDs."
    )


def normalize_sha256_list(values: list[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Validate, lower-case and de-duplicate SHA256 strings.

    Returns ``(valid, rejected)`` where each rejected entry carries the original
    value and the reason.
    """
    valid: list[str] = []
    seen: set[str] = set()
    rejected: list[dict[str, str]] = []
    for raw in values:
        candidate = (raw or "").strip().lower()
        if not candidate:
            rejected.append({"value": raw, "reason": "empty"})
            continue
        if not _SHA256_RE.match(candidate):
            rejected.append({"value": raw, "reason": "not a 64-character hex SHA256"})
            continue
        if candidate in seen:
            rejected.append({"value": raw, "reason": "duplicate in input"})
            continue
        seen.add(candidate)
        valid.append(candidate)
    return valid, rejected


# ---------------------------------------------------------------------------
# Application file rules
# ---------------------------------------------------------------------------


class ApplicationFileRule(BaseModel):
    """One application file rule, expressed as the conditions it combines.

    Mirrors the portal's "Add Rule" dialog: Full Path, Process Path, Created By
    Process and Certificate can be combined; Hash (ThreatLocker hash) and SHA256
    are standalone rules. The KB adds two constraints which are enforced here:
    ``process_path`` and ``created_by`` cannot stand alone, and a hash cannot be
    combined with any other condition.
    """

    model_config = ConfigDict(extra="forbid")

    full_path: str | None = Field(
        default=None,
        description="Full path condition. Wildcards (*) allowed, e.g. 'C:\\\\Program Files\\\\App\\\\*.exe'.",
    )
    process_path: str | None = Field(
        default=None,
        description="Process path condition (the process performing the action). Wildcards allowed. Cannot stand alone.",
    )
    created_by: str | None = Field(
        default=None,
        description="Created-by-process condition (API field `installedBy`). Wildcards allowed. Cannot stand alone.",
    )
    cert: str | None = Field(
        default=None,
        description="Certificate subject condition. No wildcards. Example: 'CN=Vendor Inc, O=Vendor Inc, ...'.",
    )
    hash: str | None = Field(
        default=None,
        description="ThreatLocker hash. Standalone — cannot be combined with other conditions.",
    )
    sha256: str | None = Field(
        default=None,
        description="SHA256 hash. Standalone — cannot be combined with other conditions. Sent in the API's `hash` field with isHashOnly=true.",
    )
    notes: str = Field(
        default="",
        description="Free-text note stored on the rule (the KB marks this required for ApplicationInsert rules).",
    )

    @model_validator(mode="after")
    def _check_combination(self) -> ApplicationFileRule:
        conditions = {
            "full_path": self.full_path,
            "process_path": self.process_path,
            "created_by": self.created_by,
            "cert": self.cert,
            "hash": self.hash,
            "sha256": self.sha256,
        }
        present = [k for k, v in conditions.items() if v not in (None, "")]
        if not present:
            raise ValueError("A rule needs at least one condition.")
        if self.hash and self.sha256:
            raise ValueError("Provide either `hash` or `sha256`, not both.")
        if (self.hash or self.sha256) and len(present) > 1:
            raise ValueError(
                "Hash / SHA256 rules are standalone and cannot be combined with other conditions."
            )
        if self.sha256 and not _SHA256_RE.match(self.sha256.strip()):
            raise ValueError("`sha256` must be a 64-character hexadecimal string.")
        if set(present) <= {"process_path", "created_by"}:
            raise ValueError(
                "`process_path` and `created_by` cannot stand alone; combine them with `full_path` or `cert`."
            )
        return self

    @property
    def is_hash_only(self) -> bool:
        return bool(self.hash or self.sha256)

    def to_application_file_dto(
        self,
        *,
        os_type: int,
        application_id: str | None = None,
        application_name: str | None = None,
        update_status: int | None = None,
    ) -> dict[str, Any]:
        """Serialise to the ApplicationFileDto shape the API expects.

        Only the condition fields that are set are emitted, which is what the
        KB asks for ("include only fields related to the rule").
        """
        dto: dict[str, Any] = {"osType": os_type, "notes": self.notes or ""}
        if application_id is not None:
            dto["applicationId"] = application_id
        if application_name is not None:
            dto["applicationName"] = application_name
        if self.full_path:
            dto["fullPath"] = self.full_path
        if self.process_path:
            dto["processPath"] = self.process_path
        if self.created_by:
            dto["installedBy"] = self.created_by
        if self.cert:
            dto["cert"] = self.cert
        if self.hash:
            dto["hash"] = self.hash.strip()
        if self.sha256:
            dto["hash"] = self.sha256.strip().lower()
        if self.is_hash_only:
            dto["isHashOnly"] = True
        if update_status is not None:
            dto["updateStatus"] = update_status
        return dto


# ---------------------------------------------------------------------------
# Action log projection / aggregation
# ---------------------------------------------------------------------------

# groupBys IDs from the KB Unified Audit article. Keys are the friendly names the
# tool accepts; the API wants the integer.
ACTION_LOG_GROUP_BY_IDS: dict[str, int] = {
    "username": 1,
    "processPath": 2,
    "processId": 3,
    "createdByProcess": 4,
    "policyId": 5,
    "policyName": 6,
    "applicationId": 7,
    "applicationName": 8,
    "actionType": 9,
    "fullPath": 10,
    "hash": 11,
    "sha256": 12,
    "fileSize": 13,
    "interface": 14,
    "certificates": 15,
    "sourceIpAddress": 16,
    "hostname": 17,  # "Asset Name" in the KB table
    "sourcePort": 18,
    "destinationPort": 19,
    "notes": 20,
    "data": 21,
    "remotePresence": 22,
    "eventLogSourceId": 23,
    "networkDirection": 24,
    "destinationIpAddress": 25,
    "cmdLineParameters": 27,
    "encryptionStatus": 29,
    "monitorOnly": 34,
    "serialNumber": 37,
    "currentThreatLevel": 42,
    "destinationDomain": 45,
    "parentProcessTlHash": 46,
    "parentProcessSha256": 47,
    "parentProcessFileSize": 48,
    "parentProcessCertificate": 49,
    "protocol": 57,
    "parentProcessApplicationId": 58,
    "additionalPolicy": 63,
    "threatLockerVersion": 64,
    "computerId": 65,
    "eventTime": 66,
    "threatType": 67,
    "resultStatus": 68,
    "location": 69,
    "riskScore": 70,
    "riskState": 71,
    "source": 72,
    "service": 73,
    "priority": 74,
    "facility": 75,
    "severity": 76,
    "activity": 77,
    "macAddress": 78,
    "packetSize": 79,
    "fullPathWithCmdLine": 80,
    "processPathWithCmdLine": 81,
}

# Aggregations that have no server-side groupBy and are computed client-side
# over paged rows. "fullPathFolder" = directory portion of fullPath.
CLIENT_SIDE_AGGREGATES: dict[str, str] = {"fullPathFolder": "fullPath"}

AggregateMode = Literal["auto", "server", "client"]


def folder_of(path: str | None) -> str:
    """Directory part of a Windows or POSIX path ('' when unknown)."""
    if not path:
        return ""
    cut = max(path.rfind("\\"), path.rfind("/"))
    return path[:cut] if cut > 0 else path


def pick_fields(row: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    """Project a row to the requested keys, matching key names case-insensitively."""
    lower_map = {k.lower(): k for k in row}
    out: dict[str, Any] = {}
    for f in fields:
        actual = lower_map.get(f.lower())
        if actual is not None:
            out[f] = row[actual]
    return out


def row_value(row: dict[str, Any], key: str) -> Any:
    """Case-insensitive single-key lookup."""
    if key in row:
        return row[key]
    lower = key.lower()
    for k, v in row.items():
        if k.lower() == lower:
            return v
    return None
