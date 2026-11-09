"""Reusable parameter annotations shared by the hand-written management tools."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

ReadOrgId = Annotated[
    str | None,
    Field(
        default=None,
        description="Override the default organization (ManagedOrganizationId header).",
    ),
]

OverrideOrgId = Annotated[
    str | None,
    Field(default=None, description="Optional OverrideManagedOrganizationId header."),
]

WriteOrgId = Annotated[
    str | None,
    Field(
        default=None,
        description=(
            "Target organization GUID for this write. Omit to target the server's configured "
            "default org (THREATLOCKER_ORG_ID). Any other org MUST be named explicitly here; "
            "write tools have no other org override."
        ),
    ),
]

DryRun = Annotated[
    bool,
    Field(
        default=True,
        description=(
            "Default true: return the exact request(s) that would be sent and the target org, "
            "and send nothing. Pass false to execute."
        ),
    ),
]

Confirm = Annotated[
    bool,
    Field(
        default=False,
        description=(
            "Required (true) in addition to dry_run=false for destructive operations. "
            "Ignored during a dry run."
        ),
    ),
]
