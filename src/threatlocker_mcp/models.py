"""Pydantic models generated from the ThreatLocker OpenAPI spec.

Do not edit by hand. Regenerate via `python scripts/generate_from_spec.py spec.json`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ActionLogCreatedByProcessesDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    created_by_process: str | None = Field(default=None, alias="createdByProcess")
    count: int | None = Field(default=None)


class Certificate(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    subject: str | None = Field(default=None)
    sha: str | None = Field(default=None)
    value: str | None = Field(default=None)
    valid_cert: bool | None = Field(default=None, alias="validCert")


class OrganizationParentsDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    organization_id: str | None = Field(default=None, alias="organizationId")
    display_name: str | None = Field(default=None, alias="displayName")


class Int32ObjectKeyValuePair(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    key: int | None = Field(default=None)
    value: Any | None = Field(default=None)


class ThreatLockerItemDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    d: str | None = Field(default=None)
    u: str | None = Field(default=None, description="Username")
    pid: str | None = Field(default=None, description="PolicyID")
    pn: str | None = Field(default=None, description="PolicyName")
    at: int | None = Field(default=None, description="ActionType")
    aid: int | None = Field(default=None, description="ActionID")
    a: list[Int32ObjectKeyValuePair] | None = Field(default=None, description="Attribute")


class EngineRating(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    name: str | None = Field(default=None)
    rating: str | None = Field(default=None)


class ActionLogDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    action_log_id: int | None = Field(default=None, alias="actionLogId")
    e_action_log_id: str | None = Field(default=None, alias="eActionLogId")
    organization_id: str | None = Field(default=None, alias="organizationId")
    computer_id: str | None = Field(default=None, alias="computerId")
    date_time: str | None = Field(default=None, alias="dateTime")
    date_time_imported: str | None = Field(default=None, alias="dateTimeImported")
    organization_name: str | None = Field(default=None, alias="organizationName")
    hostname: str | None = Field(default=None)
    username: str | None = Field(default=None)
    full_path: str | None = Field(default=None, alias="fullPath")
    policy_name: str | None = Field(default=None, alias="policyName")
    action_type: str | None = Field(default=None, alias="actionType")
    action_type_id: int | None = Field(default=None, alias="actionTypeId")
    action_id: int | None = Field(default=None, alias="actionId")
    action: str | None = Field(default=None)
    is_monitor_mode: bool | None = Field(default=None, alias="isMonitorMode")
    monitor_mode: str | None = Field(default=None, alias="monitorMode")
    learning_mode_end_date: str | None = Field(default=None, alias="learningModeEndDate")
    policy_id: str | None = Field(default=None, alias="policyId")
    policy_location: str | None = Field(default=None, alias="policyLocation")
    policy_organization_id: str | None = Field(default=None, alias="policyOrganizationId")
    process_id: int | None = Field(default=None, alias="processId")
    process_path: str | None = Field(default=None, alias="processPath")
    hash: str | None = Field(default=None)
    created_by_process: str | None = Field(default=None, alias="createdByProcess")
    data: str | None = Field(default=None)
    remote_presence: bool | None = Field(default=None, alias="remotePresence")
    remote_presence_text: str | None = Field(default=None, alias="remotePresenceText")
    remote_presence_threat_locker_detected: bool | None = Field(
        default=None, alias="remotePresenceThreatLockerDetected"
    )
    device_type: str | None = Field(default=None, alias="deviceType")
    cert: str | None = Field(default=None)
    certs: list[str] | None = Field(default=None)
    cert_exists: bool | None = Field(default=None, alias="certExists")
    certificates: list[Certificate] | None = Field(default=None)
    cert_text: str | None = Field(default=None, alias="certText")
    organization_parents: list[OrganizationParentsDto] | None = Field(
        default=None, alias="organizationParents"
    )
    application_organization_id: str | None = Field(default=None, alias="applicationOrganizationId")
    application_is_built_in: bool | None = Field(default=None, alias="applicationIsBuiltIn")
    application_id: str | None = Field(default=None, alias="applicationId")
    application_name: str | None = Field(default=None, alias="applicationName")
    notes: str | None = Field(default=None)
    serial_number: str | None = Field(default=None, alias="serialNumber")
    encryption: int | None = Field(default=None)
    size: int | None = Field(default=None)
    sha256_hash: str | None = Field(default=None, alias="sha256Hash")
    policy_exists: bool | None = Field(default=None, alias="policyExists")
    policy_enabled: bool | None = Field(default=None, alias="policyEnabled")
    storage_policy_exists: bool | None = Field(default=None, alias="storagePolicyExists")
    nac_policy_exists: bool | None = Field(default=None, alias="nacPolicyExists")
    secure_network_policy_exists: bool | None = Field(
        default=None, alias="secureNetworkPolicyExists"
    )
    tw_policy_exists: bool | None = Field(default=None, alias="twPolicyExists")
    web_control_policy_exists: bool | None = Field(default=None, alias="webControlPolicyExists")
    option_to_request: bool | None = Field(default=None, alias="optionToRequest")
    allow_permit_vendor_button: bool | None = Field(default=None, alias="allowPermitVendorButton")
    effective_action: str | None = Field(default=None, alias="effectiveAction")
    encryption_status: str | None = Field(default=None, alias="encryptionStatus")
    report_missing: bool | None = Field(default=None, alias="reportMissing")
    virus_total_check_name: str | None = Field(default=None, alias="virusTotalCheckName")
    virus_total_check_argument: str | None = Field(default=None, alias="virusTotalCheckArgument")
    os_type: int | None = Field(default=None, alias="osType")
    is_extension: bool | None = Field(default=None, alias="isExtension")
    edge_store_url: str | None = Field(default=None, alias="edgeStoreUrl")
    chrome_store_url: str | None = Field(default=None, alias="chromeStoreUrl")
    firefox_store_url: str | None = Field(default=None, alias="firefoxStoreUrl")
    action_log_created_by_processes: list[ActionLogCreatedByProcessesDto] | None = Field(
        default=None, alias="actionLogCreatedByProcesses"
    )
    total_count: int | None = Field(default=None, alias="totalCount")
    last_sort_value: int | None = Field(default=None, alias="lastSortValue")
    network_direction: int | None = Field(default=None, alias="networkDirection")
    source_i_p_address: str | None = Field(default=None, alias="sourceIPAddress")
    destination_i_p_address: str | None = Field(default=None, alias="destinationIPAddress")
    group_by_count: int | None = Field(default=None, alias="groupByCount")
    destination_port: str | None = Field(default=None, alias="destinationPort")
    batch_id: str | None = Field(default=None, alias="batchId")
    is_protected_process: bool | None = Field(default=None, alias="isProtectedProcess")
    memory_bytes: int | None = Field(default=None, alias="memoryBytes")
    process_name: str | None = Field(default=None, alias="processName")
    parent_process_id: int | None = Field(default=None, alias="parentProcessId")
    parent_process_name: str | None = Field(default=None, alias="parentProcessName")
    has_view_computer_permission: bool | None = Field(
        default=None, alias="hasViewComputerPermission"
    )
    allow_file_upload: bool | None = Field(default=None, alias="allowFileUpload")
    can_view_on_system_lookup: bool | None = Field(default=None, alias="canViewOnSystemLookup")
    system_lookup_url: str | None = Field(default=None, alias="systemLookupUrl")
    has_policy_data: bool | None = Field(default=None, alias="hasPolicyData")
    threat_locker_item: ThreatLockerItemDto | None = Field(default=None, alias="threatLockerItem")
    integration_type_id: str | None = Field(default=None, alias="integrationTypeId")
    is_cloud_log: bool | None = Field(default=None, alias="isCloudLog")
    is_cloud_action_type: bool | None = Field(default=None, alias="isCloudActionType")
    threat_severity_level: str | None = Field(default=None, alias="threatSeverityLevel")
    engine_ratings: list[EngineRating] | None = Field(default=None, alias="engineRatings")
    is_virus_total_unavailable: bool | None = Field(default=None, alias="isVirusTotalUnavailable")
    delete_file_request_sent: bool | None = Field(default=None, alias="deleteFileRequestSent")
    is_access_device: bool | None = Field(default=None, alias="isAccessDevice")


class ParamsFieldsDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    name: str | None = Field(default=None)
    filter_type: int | None = Field(default=None, alias="filterType")
    field_type: int | None = Field(default=None, alias="fieldType")
    value: str | None = Field(default=None)
    label: str | None = Field(default=None)
    dropdown_label: str | None = Field(default=None, alias="dropdownLabel")
    is_drop_down: bool | None = Field(default=None, alias="isDropDown")
    guid_value: str | None = Field(default=None, alias="guidValue")
    numeric_value: int | None = Field(default=None, alias="numericValue")
    long_value: int | None = Field(default=None, alias="longValue")
    bool_value: bool | None = Field(default=None, alias="boolValue")
    date_time_value: str | None = Field(default=None, alias="dateTimeValue")
    field_attribute_id: int | None = Field(default=None, alias="fieldAttributeId")
    list_value: list[str] | None = Field(default=None, alias="listValue")
    list_guid_value: list[str] | None = Field(default=None, alias="listGuidValue")
    list_numeric_value: list[int] | None = Field(default=None, alias="listNumericValue")
    list_long_value: list[int] | None = Field(default=None, alias="listLongValue")
    date_time_interval: list[str] | None = Field(default=None, alias="dateTimeInterval")


class ActionLogParamsDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    action_type: str | None = Field(default=None, alias="actionType")
    source_table_id: int | None = Field(default=None, alias="sourceTableId")
    action_log_id: int | None = Field(default=None, alias="actionLogId")
    policy_id: str | None = Field(default=None, alias="policyId")
    action_id: int | None = Field(default=None, alias="actionId")
    filter: str | None = Field(default=None)
    show_child_organizations: bool | None = Field(default=None, alias="showChildOrganizations")
    simulate_deny: bool | None = Field(default=None, alias="simulateDeny")
    only_true_denies: bool | None = Field(default=None, alias="onlyTrueDenies")
    username: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    process_id: int | None = Field(default=None, alias="processId")
    full_path: str | None = Field(default=None, alias="fullPath")
    device_type: str | None = Field(default=None, alias="deviceType")
    date_time: list[str] | None = Field(default=None, alias="dateTime")
    group_by: str | None = Field(default=None, alias="groupBy")
    page_number: int | None = Field(default=None, alias="pageNumber")
    page_size: int | None = Field(default=None, alias="pageSize")
    params_fields_dto: list[ParamsFieldsDto] | None = Field(default=None, alias="paramsFieldsDto")
    start_date: str | None = Field(default=None, alias="startDate")
    end_date: str | None = Field(default=None, alias="endDate")
    date_time_last_imported: str | None = Field(default=None, alias="dateTimeLastImported")
    show_total_count: bool | None = Field(default=None, alias="showTotalCount")
    get_new_count: bool | None = Field(default=None, alias="getNewCount")
    export_mode: bool | None = Field(default=None, alias="exportMode")
    total_rows: int | None = Field(default=None, alias="totalRows")
    use_e_id: bool | None = Field(default=None, alias="useEId")
    last_sort_value: int | None = Field(default=None, alias="lastSortValue")
    sort_by: str | None = Field(default=None, alias="sortBy")
    sort_descending: bool | None = Field(default=None, alias="sortDescending")
    group_bys: list[int] | None = Field(default=None, alias="groupBys")
    action_types: list[str] | None = Field(default=None, alias="actionTypes")
    show_known_threats_only: bool | None = Field(default=None, alias="showKnownThreatsOnly")
    has_policy_id: bool | None = Field(default=None, alias="hasPolicyId")


class FilePolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    file_policy_id: str | None = Field(default=None, alias="filePolicyId")
    path: str | None = Field(default=None)
    action: int | None = Field(default=None, description="1 = Permit, 2 = Deny")
    permission: int | None = Field(default=None, description="1 = Read, 2 = Write")


class NetworkPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    network_policy_id: str | None = Field(default=None, alias="networkPolicyId")
    server: str | None = Field(default=None)
    port: int | None = Field(default=None)
    action: int | None = Field(default=None, description="1 = Permit, 2 = Deny")
    server_display_name: str | None = Field(default=None, alias="serverDisplayName")


class RegistryPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    registry_policy_id: str | None = Field(default=None, alias="registryPolicyId")
    path: str | None = Field(default=None)
    action: int | None = Field(default=None, description="1 = Permit, 2 = Deny")
    permission: int | None = Field(default=None, description="1 = Read, 2 = Write")


class AssociatedApplicationPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    name: str | None = Field(default=None)
    application_id: str | None = Field(default=None, alias="applicationId")
    os_type: int | None = Field(default=None, alias="osType")


class AdvRFPolicy(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    hide_custom_rules: bool | None = Field(default=None, alias="hideCustomRules")
    restrict_application_spawning: bool | None = Field(
        default=None, alias="restrictApplicationSpawning"
    )
    restrict_registry_access: bool | None = Field(default=None, alias="restrictRegistryAccess")
    restrict_file_access: bool | None = Field(default=None, alias="restrictFileAccess")
    restrict_network_access: bool | None = Field(default=None, alias="restrictNetworkAccess")
    restrict_application: bool | None = Field(default=None, alias="restrictApplication")
    rf_file_policy: list[FilePolicy] | None = Field(default=None, alias="rfFilePolicy")
    rf_network_policy: list[NetworkPolicy] | None = Field(default=None, alias="rfNetworkPolicy")
    rf_registry_policy: list[RegistryPolicy] | None = Field(default=None, alias="rfRegistryPolicy")
    rf_associated_application_policy: list[AssociatedApplicationPolicy] | None = Field(
        default=None, alias="rfAssociatedApplicationPolicy"
    )


UpdateStatus = int


class ApplicationFileDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    application_file_id: int | None = Field(default=None, alias="applicationFileId")
    application_id: str | None = Field(default=None, alias="applicationId")
    full_path: str | None = Field(default=None, alias="fullPath")
    cert: str | None = Field(default=None)
    hash: str | None = Field(default=None)
    process_path: str | None = Field(default=None, alias="processPath")
    notes: str | None = Field(default=None)
    installed_by: str | None = Field(default=None, alias="installedBy")
    name: str | None = Field(default=None)
    application_file_details: str | None = Field(default=None, alias="applicationFileDetails")
    key_file: bool | None = Field(default=None, alias="keyFile")
    original_full_path: str | None = Field(default=None, alias="originalFullPath")
    original_cert: str | None = Field(default=None, alias="originalCert")
    original_hash: str | None = Field(default=None, alias="originalHash")
    original_process_path: str | None = Field(default=None, alias="originalProcessPath")
    original_notes: str | None = Field(default=None, alias="originalNotes")
    original_installed_by: str | None = Field(default=None, alias="originalInstalledBy")
    original_key_file: bool | None = Field(default=None, alias="originalKeyFile")
    os_type: int | None = Field(default=None, alias="osType")
    is_hash_only: bool | None = Field(default=None, alias="isHashOnly")
    min_size: int | None = Field(default=None, alias="minSize")
    max_size: int | None = Field(default=None, alias="maxSize")
    update_status: UpdateStatus | None = Field(default=None, alias="updateStatus")
    created_by: str | None = Field(default=None, alias="createdBy")
    application_name: str | None = Field(default=None, alias="applicationName")
    organization_id: str | None = Field(default=None, alias="organizationId")


class ThreatLockerCertDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    sha: str | None = Field(default=None)
    subject: str | None = Field(default=None)
    valid_cert: bool | None = Field(default=None, alias="validCert")


class ApplicationMatchParameterDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    hash: str | None = Field(default=None)
    sha256: str | None = Field(default=None)
    path: str | None = Field(default=None)
    process_path: str | None = Field(default=None, alias="processPath")
    organization_ids: list[str] | None = Field(default=None, alias="organizationIds")
    certs: list[ThreatLockerCertDto] | None = Field(default=None)
    created_bys: list[str] | None = Field(default=None, alias="createdBys")
    os_type: int | None = Field(default=None, alias="osType")
    filename: str | None = Field(default=None)
    folder: str | None = Field(default=None)
    approval_request_id: str | None = Field(default=None, alias="approvalRequestId")
    built_in_partial_matching_files: list[ApplicationFileDto] | None = Field(
        default=None, alias="builtInPartialMatchingFiles"
    )


class ApplicationOnlineDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    name: str | None = Field(default=None)
    application_name: str | None = Field(default=None, alias="applicationName")
    application_id: str | None = Field(default=None, alias="applicationId")
    organization_id: str | None = Field(default=None, alias="organizationId")
    organization_name: str | None = Field(default=None, alias="organizationName")
    os_type: int | None = Field(default=None, alias="osType")
    suggested_policy_id: str | None = Field(default=None, alias="suggestedPolicyId")
    status: int | None = Field(default=None)
    is_maintained: bool | None = Field(default=None, alias="isMaintained")
    research_application_id: str | None = Field(default=None, alias="researchApplicationId")


class ThreatLockerActionDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    fullpath: str | None = Field(default=None)
    policyid: str | None = Field(default=None)
    username: str | None = Field(default=None)
    actionid: int | None = Field(default=None)
    hash: str | None = Field(default=None)
    process_name: str | None = Field(default=None, alias="processName")
    certs: list[ThreatLockerCertDto] | None = Field(default=None)
    application_id: str | None = Field(default=None, alias="applicationId")
    datetime: str | None = Field(default=None)
    log_action: bool | None = Field(default=None, alias="logAction")
    serial_number: str | None = Field(default=None, alias="SerialNumber")
    device_type: str | None = Field(default=None, alias="deviceType")
    action_type: str | None = Field(default=None, alias="actionType")
    size: int | None = Field(default=None)
    process_id: int | None = Field(default=None, alias="processId")
    ring_fence: bool | None = Field(default=None, alias="ringFence")
    policy_name: str | None = Field(default=None, alias="policyName")
    application_name: str | None = Field(default=None, alias="applicationName")
    encryption_status: int | None = Field(default=None, alias="encryptionStatus")
    installed_by: list[str] | None = Field(default=None, alias="installedBy")
    monitor_only: bool | None = Field(default=None, alias="monitorOnly")
    notes: str | None = Field(default=None)
    sha256: str | None = Field(default=None)
    ringfence_policy_id: str | None = Field(default=None, alias="ringfencePolicyId")
    remote_presence: bool | None = Field(default=None, alias="remotePresence")
    organization_id: str | None = Field(default=None, alias="organizationId")
    hostname: str | None = Field(default=None)
    computer_id: str | None = Field(default=None, alias="computerId")
    manufacturer: str | None = Field(default=None)
    os_type: int | None = Field(default=None, alias="osType")
    destination_i_p: str | None = Field(default=None, alias="destinationIP")
    domain_name: str | None = Field(default=None, alias="DomainName")
    organization_name: str | None = Field(default=None, alias="organizationName")


class ApprovalRequestTimerDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    approval_request_id: str | None = Field(default=None, alias="approvalRequestId")
    request_date: str | None = Field(default=None, alias="requestDate")
    assigned_date: str | None = Field(default=None, alias="assignedDate")
    escalated_date: str | None = Field(default=None, alias="escalatedDate")
    returned_date: str | None = Field(default=None, alias="returnedDate")
    reassigned_date: str | None = Field(default=None, alias="reassignedDate")
    actioned_date: str | None = Field(default=None, alias="actionedDate")
    total_time_in_seconds: int | None = Field(default=None, alias="totalTimeInSeconds")


class ApprovalRequestDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    status_id_escalated_to_m_s_p: int | None = Field(default=None, alias="statusIdEscalatedToMSP")
    status_id_escalated_by_customer: int | None = Field(
        default=None, alias="statusIdEscalatedByCustomer"
    )
    master_organization_id: str | None = Field(default=None, alias="masterOrganizationId")
    approved_by: str | None = Field(default=None, alias="approvedBy")
    approval_request_id: str | None = Field(default=None, alias="approvalRequestId")
    date_time: str | None = Field(default=None, alias="dateTime")
    path: str | None = Field(default=None)
    hash: str | None = Field(default=None)
    username: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    status_id: int | None = Field(default=None, alias="statusId")
    computer_id: str | None = Field(default=None, alias="computerId")
    organization_name: str | None = Field(default=None, alias="organizationName")
    json_: str | None = Field(default=None, alias="json")
    ticket_id: str | None = Field(default=None, alias="ticketId")
    requestor: str | None = Field(default=None)
    requestor_reason: str | None = Field(default=None, alias="requestorReason")
    requestor_email_address: str | None = Field(default=None, alias="requestorEmailAddress")
    comments: str | None = Field(default=None)
    action_date: str | None = Field(default=None, alias="actionDate")
    organization_id: str | None = Field(default=None, alias="organizationId")
    multi_level_approval_request_id: str | None = Field(
        default=None, alias="multiLevelApprovalRequestId"
    )
    approval_number: int | None = Field(default=None, alias="approvalNumber")
    approved_by_tier_level: int | None = Field(default=None, alias="approvedByTierLevel")
    temp_policy_id: str | None = Field(default=None, alias="tempPolicyId")
    policy_id: str | None = Field(default=None, alias="policyId")
    temp_application_id: str | None = Field(default=None, alias="tempApplicationId")
    application_id: str | None = Field(default=None, alias="applicationId")
    multi_level_approval_status_id: int | None = Field(
        default=None, alias="multiLevelApprovalStatusId"
    )
    initial_approval_tier_level: int | None = Field(default=None, alias="initialApprovalTierLevel")
    approval_count: int | None = Field(default=None, alias="approvalCount")
    pending_tier_level: int | None = Field(default=None, alias="pendingTierLevel")
    has_pending_approval_request: bool | None = Field(
        default=None, alias="hasPendingApprovalRequest"
    )
    ip_address: str | None = Field(default=None, alias="ipAddress")
    is_assigned: bool | None = Field(default=None, alias="isAssigned")
    assignee_user_id: str | None = Field(default=None, alias="assigneeUserId")
    threat_locker_data_center_id: str | None = Field(default=None, alias="threatLockerDataCenterId")
    instance_name: str | None = Field(default=None, alias="instanceName")
    assignee_username: str | None = Field(default=None, alias="assigneeUsername")
    assignee_first_name: str | None = Field(default=None, alias="assigneeFirstName")
    assignee_lastname: str | None = Field(default=None, alias="assigneeLastname")
    threat_locker_action_dto: ThreatLockerActionDto | None = Field(
        default=None, alias="threatLockerActionDto"
    )
    notes: str | None = Field(default=None)
    signature: str | None = Field(default=None)
    tl_instructions: str | None = Field(default=None, alias="tlInstructions")
    suggest_custom_rule: bool | None = Field(default=None, alias="suggestCustomRule")
    authorize_for_permit: bool | None = Field(default=None, alias="authorizeForPermit")
    portal_api_url: str | None = Field(default=None, alias="portalApiUrl")
    cyber_hero_management_configured: bool | None = Field(
        default=None, alias="cyberHeroManagementConfigured"
    )
    max_triggered_start_date: str | None = Field(default=None, alias="maxTriggeredStartDate")
    is_escalated_by_cyber_hero: bool | None = Field(default=None, alias="isEscalatedByCyberHero")
    is_escalated_by_customer: bool | None = Field(default=None, alias="isEscalatedByCustomer")
    ticket_approval_manager: str | None = Field(default=None, alias="ticketApprovalManager")
    show_mfa_challenge: bool | None = Field(default=None, alias="showMfaChallenge")
    show_mfa_registration: bool | None = Field(default=None, alias="showMfaRegistration")
    linked_mfa_user: str | None = Field(default=None, alias="linkedMfaUser")
    serial_number: str | None = Field(default=None, alias="serialNumber")
    approval_request_timer_dto: ApprovalRequestTimerDto | None = Field(
        default=None, alias="approvalRequestTimerDto"
    )
    can_request_new_built_in: bool | None = Field(default=None, alias="canRequestNewBuiltIn")
    is_assignee_logged_into_master: bool | None = Field(
        default=None, alias="isAssigneeLoggedIntoMaster"
    )
    retrieved_assignee_username: bool | None = Field(
        default=None, alias="retrievedAssigneeUsername"
    )
    count: int | None = Field(default=None)


class ApprovalRequestParametersDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    status_id: int | None = Field(default=None, alias="statusId")
    search_text: str | None = Field(default=None, alias="searchText")
    user_approval_tier_level: int | None = Field(default=None, alias="userApprovalTierLevel")
    show_current_tier_only: bool | None = Field(default=None, alias="showCurrentTierOnly")
    show_child_organizations: bool | None = Field(default=None, alias="showChildOrganizations")
    request_type_id: int | None = Field(default=None, alias="requestTypeId")
    order_by: str | None = Field(default=None, alias="orderBy")
    is_ascending: bool | None = Field(default=None, alias="isAscending")
    action_type: list[str] | None = Field(default=None, alias="actionType")
    page_size: int | None = Field(default=None, alias="pageSize")
    page_number: int | None = Field(default=None, alias="pageNumber")


class ApprovalRequestUpdateParametersDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    approval_request_dtos: list[ApprovalRequestDto] | None = Field(
        default=None, alias="approvalRequestDtos"
    )
    type_: str | None = Field(default=None, alias="type")
    ignore_subject: str | None = Field(default=None, alias="ignoreSubject")
    ignore_reason: str | None = Field(default=None, alias="ignoreReason")
    response_subject: str | None = Field(default=None, alias="responseSubject")
    response_reason: str | None = Field(default=None, alias="responseReason")
    reject_reason: str | None = Field(default=None, alias="rejectReason")
    is_v_d_i: bool | None = Field(default=None, alias="isVDI")
    notify_on_ignore: bool | None = Field(default=None, alias="notifyOnIgnore")
    notify_on_response: bool | None = Field(default=None, alias="notifyOnResponse")
    using_custom_approvals: bool | None = Field(default=None, alias="usingCustomApprovals")
    allowed_approval_request_dtos: list[ApprovalRequestDto] | None = Field(
        default=None, alias="allowedApprovalRequestDtos"
    )
    denied_approval_request_dtos: list[ApprovalRequestDto] | None = Field(
        default=None, alias="deniedApprovalRequestDtos"
    )


class ComputerDataForDisableProtectionDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    action: str | None = Field(default=None)
    computer_group_id: str | None = Field(default=None, alias="computerGroupId")
    computer_id: str | None = Field(default=None, alias="computerId")
    computer_name: str | None = Field(default=None, alias="computerName")
    maintenance_end_date: str | None = Field(default=None, alias="maintenanceEndDate")
    organization_id: str | None = Field(default=None, alias="organizationId")
    start_date_time: str | None = Field(default=None, alias="startDateTime")


class ComputerDataForEnableProtectionDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    applies_to_type: str | None = Field(default=None, alias="appliesToType")
    computer_id: str | None = Field(default=None, alias="computerId")
    computer_install_date: str | None = Field(default=None, alias="computerInstallDate")
    computer_name: str | None = Field(default=None, alias="computerName")
    maintenance_end_date: str | None = Field(default=None, alias="maintenanceEndDate")
    maintenance_type_id: int | None = Field(default=None, alias="maintenanceTypeId")
    organization_id: str | None = Field(default=None, alias="organizationId")
    start_date_time: str | None = Field(default=None, alias="startDateTime")


class ComputerDataForRescanBaselineDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_id: str | None = Field(default=None, alias="computerId")
    organization_id: str | None = Field(default=None, alias="organizationId")
    computer_group_id: str | None = Field(default=None, alias="computerGroupId")
    computer_name: str | None = Field(default=None, alias="computerName")


class ComputerDataForTransferDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_group_id: str | None = Field(default=None, alias="computerGroupId")
    computer_id: str | None = Field(default=None, alias="computerId")
    computer_name: str | None = Field(default=None, alias="computerName")
    group: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    maintenance_type_id: int | None = Field(default=None, alias="maintenanceTypeId")
    operating_system: str | None = Field(default=None, alias="operatingSystem")
    organization: str | None = Field(default=None)
    organization_id: str | None = Field(default=None, alias="organizationId")
    os_type: int | None = Field(default=None, alias="osType")


class ComputerDataForUpdateModeDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    action: str | None = Field(default=None)
    computer_id: str | None = Field(default=None, alias="computerId")
    computer_group_id: str | None = Field(default=None, alias="computerGroupId")
    computer_name: str | None = Field(default=None, alias="computerName")
    computer_install_date: str | None = Field(default=None, alias="computerInstallDate")
    is_isolated: bool | None = Field(default=None, alias="isIsolated")
    is_locked_out: bool | None = Field(default=None, alias="isLockedOut")
    last_version_change: str | None = Field(default=None, alias="lastVersionChange")
    maintenance_type_id: int | None = Field(default=None, alias="maintenanceTypeId")
    maintenance_end_date: str | None = Field(default=None, alias="maintenanceEndDate")
    organization_id: str | None = Field(default=None, alias="organizationId")
    os_type: int | None = Field(default=None, alias="osType")
    pending_base_files: bool | None = Field(default=None, alias="pendingBaseFiles")
    threat_locker_version: str | None = Field(default=None, alias="threatLockerVersion")
    threat_locker_version_id: str | None = Field(default=None, alias="threatLockerVersionId")
    threat_locker_version_group: str | None = Field(default=None, alias="threatLockerVersionGroup")
    threat_locker_version_group_id: str | None = Field(
        default=None, alias="threatLockerVersionGroupId"
    )


class ComputerDisabledProtectionDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_detail_dtos: list[ComputerDataForDisableProtectionDto] | None = Field(
        default=None, alias="computerDetailDtos"
    )
    end_date: str | None = Field(default=None, alias="endDate")
    start_date: str | None = Field(default=None, alias="startDate")
    maintenance_mode_type: int | None = Field(default=None, alias="maintenanceModeType")
    permit_end: bool | None = Field(default=None, alias="permitEnd")
    application_id: str | None = Field(default=None, alias="applicationId")


class ComputerEnableProtectionDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_detail_dtos: list[ComputerDataForEnableProtectionDto] | None = Field(
        default=None, alias="computerDetailDtos"
    )


class ComputerGroupItemDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_group_id: str | None = Field(default=None, alias="computerGroupId")
    name: str | None = Field(default=None)
    organization_id: str | None = Field(default=None, alias="organizationId")
    organization_name: str | None = Field(default=None, alias="organizationName")
    default: bool | None = Field(default=None)
    os_type: int | None = Field(default=None, alias="osType")
    is_global: bool | None = Field(default=None, alias="isGlobal")


class ComputerParameterDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    search_text: str | None = Field(default=None, alias="searchText")
    computer_group: str | None = Field(default=None, alias="computerGroup")
    order_by: str | None = Field(default=None, alias="orderBy")
    page_size: int | None = Field(default=None, alias="pageSize")
    page_number: int | None = Field(default=None, alias="pageNumber")
    child_organizations: bool | None = Field(default=None, alias="childOrganizations")
    action: str | None = Field(default=None)
    is_ascending: bool | None = Field(default=None, alias="isAscending")
    kind_of_action: str | None = Field(default=None, alias="kindOfAction")
    computer_id: str | None = Field(default=None, alias="computerId")
    show_last_check_in: bool | None = Field(default=None, alias="showLastCheckIn")
    show_deleted: bool | None = Field(default=None, alias="showDeleted")
    search_by: int | None = Field(default=None, alias="searchBy")
    threatlocker_version: str | None = Field(default=None, alias="threatlockerVersion")
    is_export: bool | None = Field(default=None, alias="isExport")


class ComputerRescanBaselineDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_detail_dtos: list[ComputerDataForRescanBaselineDto] | None = Field(
        default=None, alias="computerDetailDtos"
    )
    enable_learning: bool | None = Field(default=None, alias="enableLearning")


class ComputerTransferDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_detail_dtos: list[ComputerDataForTransferDto] | None = Field(
        default=None, alias="computerDetailDtos"
    )
    enable_learning_rescan: bool | None = Field(default=None, alias="enableLearningRescan")
    target_computer_group_id: str | None = Field(default=None, alias="targetComputerGroupId")
    target_organization_id: str | None = Field(default=None, alias="targetOrganizationId")


class ComputerUpdateDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_id: str | None = Field(default=None, alias="computerId")
    computer_group_id: str | None = Field(default=None, alias="computerGroupId")
    name: str | None = Field(default=None)
    use_proxy_server: bool | None = Field(default=None, alias="useProxyServer")
    proxy_server_option: str | None = Field(default=None, alias="proxyServerOption")
    proxy_url_entry: str | None = Field(default=None, alias="proxyUrlEntry")
    proxy_u_r_l: str | None = Field(default=None, alias="proxyURL")
    options: list[str] | None = Field(default=None)


class ComputerUpdateMaintenanceModeDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    application_id: str | None = Field(default=None, alias="applicationId")
    computer_detail_dto: ComputerDataForUpdateModeDto | None = Field(
        default=None, alias="computerDetailDto"
    )


class MaintenanceApplicationDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    application_id: str | None = Field(default=None, alias="applicationId")
    application_name: str | None = Field(default=None, alias="applicationName")
    create_application_only: bool | None = Field(default=None, alias="createApplicationOnly")
    applies_to_id: str | None = Field(default=None, alias="appliesToId")


class MaintenanceExistingApplicationDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    application_id: str | None = Field(default=None, alias="applicationId")
    name: str | None = Field(default=None)


class MaintenanceModeConditionsDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    maintenance_mode_condition_type_id: int | None = Field(
        default=None, alias="maintenanceModeConditionTypeId"
    )
    value: str | None = Field(default=None)


class MaintenanceModeEndDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    applies_to_type: int | None = Field(default=None, alias="appliesToType")
    computer_id: str | None = Field(default=None, alias="computerId")
    computer_install_date: str | None = Field(default=None, alias="computerInstallDate")
    end_date_time: str | None = Field(default=None, alias="endDateTime")
    maintenance_mode_id: str | None = Field(default=None, alias="maintenanceModeId")
    maintenance_type_id: int | None = Field(default=None, alias="maintenanceTypeId")
    start_date_time: str | None = Field(default=None, alias="startDateTime")


class MaintenanceModeInsertDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    all_users: bool | None = Field(default=None, alias="allUsers")
    automatic_application: bool | None = Field(default=None, alias="automaticApplication")
    automatic_application_type: int | None = Field(default=None, alias="automaticApplicationType")
    computer_id: str | None = Field(default=None, alias="computerId")
    create_new_application: bool | None = Field(default=None, alias="createNewApplication")
    end_date_time: str | None = Field(default=None, alias="endDateTime")
    existing_application: MaintenanceExistingApplicationDto | None = Field(
        default=None, alias="existingApplication"
    )
    maintenance_type_id: int | None = Field(default=None, alias="maintenanceTypeId")
    new_application: MaintenanceApplicationDto | None = Field(default=None, alias="newApplication")
    permit_end: bool | None = Field(default=None, alias="permitEnd")
    start_date_time: str | None = Field(default=None, alias="startDateTime")
    use_existing_application: bool | None = Field(default=None, alias="useExistingApplication")
    users_list: list[str] | None = Field(default=None, alias="usersList")
    computer_date_time: str | None = Field(default=None, alias="computerDateTime")
    maintenance_mode_conditions: list[MaintenanceModeConditionsDto] | None = Field(
        default=None, alias="maintenanceModeConditions"
    )
    ticket_number: str | None = Field(default=None, alias="ticketNumber")
    notes: str | None = Field(default=None)


class NetworkExclusionDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    policy_id: str | None = Field(default=None, alias="policyId")
    tag_prefix_type_id: int | None = Field(default=None, alias="tagPrefixTypeId")
    value: str | None = Field(default=None)


class PermitAdminNotes(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    ticket: str | None = Field(default=None)
    requestor_email: str | None = Field(default=None, alias="requestorEmail")
    comments: str | None = Field(default=None)


class PermitFileDetails(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    full_path: str | None = Field(default=None, alias="fullPath")
    process_path: str | None = Field(default=None, alias="processPath")
    hash: str | None = Field(default=None)
    certificates: list[ThreatLockerCertDto] | None = Field(default=None)
    created_by_processes: list[str] | None = Field(default=None, alias="createdByProcesses")
    filename: str | None = Field(default=None)
    sha256: str | None = Field(default=None)
    date: str | None = Field(default=None)
    original_hostname: str | None = Field(default=None, alias="originalHostname")
    hostname: str | None = Field(default=None)
    username: str | None = Field(default=None)
    organization_name: str | None = Field(default=None, alias="organizationName")
    policy_name: str | None = Field(default=None, alias="policyName")
    application_name: str | None = Field(default=None, alias="applicationName")
    requestor_reason: str | None = Field(default=None, alias="requestorReason")
    approval_status: str | None = Field(default=None, alias="approvalStatus")
    approval_by: str | None = Field(default=None, alias="approvalBy")
    size: int | None = Field(default=None)


class PermitMatchingApplications(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    has_matching_application: bool | None = Field(default=None, alias="hasMatchingApplication")
    use_matching_application: bool | None = Field(default=None, alias="useMatchingApplication")
    matching_application: ApplicationOnlineDto | None = Field(
        default=None, alias="matchingApplication"
    )
    use_existing_application: bool | None = Field(default=None, alias="useExistingApplication")
    existing_application: ApplicationOnlineDto | None = Field(
        default=None, alias="existingApplication"
    )
    use_new_application: bool | None = Field(default=None, alias="useNewApplication")
    new_application_name: str | None = Field(default=None, alias="newApplicationName")


class PolicyManualOption(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    full_path: str | None = Field(default=None, alias="fullPath")
    process_path: str | None = Field(default=None, alias="processPath")
    cert: str | None = Field(default=None)
    hash: str | None = Field(default=None)
    created_by: str | None = Field(default=None, alias="createdBy")
    is_default_option: bool | None = Field(default=None, alias="isDefaultOption")
    disabled: bool | None = Field(default=None)


class PermitPolicyConditions(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    use_existing_policy: bool | None = Field(default=None, alias="useExistingPolicy")
    create_manual_policy: bool | None = Field(default=None, alias="createManualPolicy")
    manual_options: list[PolicyManualOption] | None = Field(default=None, alias="manualOptions")
    rule_id: int | None = Field(default=None, alias="ruleId")
    cert_subjects: list[str] | None = Field(default=None, alias="certSubjects")
    created_by_processes: list[str] | None = Field(default=None, alias="createdByProcesses")
    disable_protection: bool | None = Field(default=None, alias="disableProtection")
    included_additional_files: list[ActionLogDto] | None = Field(
        default=None, alias="includedAdditionalFiles"
    )


class PermitPolicyLevel(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    can_use_entire_organization: bool | None = Field(default=None, alias="canUseEntireOrganization")
    to_entire_organization: bool | None = Field(default=None, alias="toEntireOrganization")
    to_computer_group: bool | None = Field(default=None, alias="toComputerGroup")
    selected_computer_group: ComputerGroupItemDto | None = Field(
        default=None, alias="selectedComputerGroup"
    )
    to_computer: bool | None = Field(default=None, alias="toComputer")


class SystemAuditDetails(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    page: str | None = Field(default=None)
    function: str | None = Field(default=None)
    object_id: str | None = Field(default=None, alias="objectId")
    details: str | None = Field(default=None)


class SystemAuditItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    organization_id: str | None = Field(default=None, alias="organizationId")
    user_id: str | None = Field(default=None, alias="userId")
    username: str | None = Field(default=None)
    action: str | None = Field(default=None)
    ip_address: str | None = Field(default=None, alias="ipAddress")
    effective_action: str | None = Field(default=None, alias="effectiveAction")
    details: SystemAuditDetails | None = Field(default=None)
    master_view_only: bool | None = Field(default=None, alias="masterViewOnly")
    date_time: str | None = Field(default=None, alias="dateTime")
    system_audit_id: str | None = Field(default=None, alias="systemAuditId")
    system_audit_object_type_id: int | None = Field(default=None, alias="systemAuditObjectTypeId")
    organization_name: str | None = Field(default=None, alias="organizationName")
    ticket_number: str | None = Field(default=None, alias="ticketNumber")
    notes: str | None = Field(default=None)


class PermitApplicationDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    computer_id: str | None = Field(default=None, alias="computerId")
    computer_group_id: str | None = Field(default=None, alias="computerGroupId")
    organization_id: str | None = Field(default=None, alias="organizationId")
    organization_ids: list[str] | None = Field(default=None, alias="organizationIds")
    os_type: int | None = Field(default=None, alias="osType")
    user_instance: str | None = Field(default=None, alias="userInstance")
    approval_request: ApprovalRequestDto | None = Field(default=None, alias="approvalRequest")
    is_from_approval: bool | None = Field(default=None, alias="isFromApproval")
    action_log: ActionLogDto | None = Field(default=None, alias="actionLog")
    is_from_action_log: bool | None = Field(default=None, alias="isFromActionLog")
    action_type: str | None = Field(default=None, alias="actionType")
    is_elevation_request: bool | None = Field(default=None, alias="isElevationRequest")
    is_extension_request: bool | None = Field(default=None, alias="isExtensionRequest")
    edge_store_url: str | None = Field(default=None, alias="edgeStoreUrl")
    chrome_store_url: str | None = Field(default=None, alias="chromeStoreUrl")
    can_view_on_system_lookup: bool | None = Field(default=None, alias="canViewOnSystemLookup")
    system_lookup_url: str | None = Field(default=None, alias="systemLookupUrl")
    can_view_virus_total: bool | None = Field(default=None, alias="canViewVirusTotal")
    virus_total_url: str | None = Field(default=None, alias="virusTotalUrl")
    file_history_checked: bool | None = Field(default=None, alias="fileHistoryChecked")
    suggest_custom_rule: bool | None = Field(default=None, alias="suggestCustomRule")
    file_details: PermitFileDetails | None = Field(default=None, alias="fileDetails")
    matching_applications: PermitMatchingApplications | None = Field(
        default=None, alias="matchingApplications"
    )
    policy_conditions: PermitPolicyConditions | None = Field(default=None, alias="policyConditions")
    policy_expiration_date: str | None = Field(default=None, alias="policyExpirationDate")
    ringfencing_options: AdvRFPolicy | None = Field(default=None, alias="ringfencingOptions")
    network_exclusions: list[NetworkExclusionDto] | None = Field(
        default=None, alias="networkExclusions"
    )
    ringfence_action_id: int | None = Field(default=None, alias="ringfenceActionId")
    is_ringfenced: bool | None = Field(default=None, alias="isRingfenced")
    has_ringfencing_as_product: bool | None = Field(default=None, alias="hasRingfencingAsProduct")
    has_elevation: bool | None = Field(default=None, alias="hasElevation")
    organization_has_elevation: bool | None = Field(default=None, alias="organizationHasElevation")
    elevation_status: int | None = Field(default=None, alias="elevationStatus")
    elevation_expiration: int | None = Field(default=None, alias="elevationExpiration")
    elevation_expiration_date: str | None = Field(default=None, alias="elevationExpirationDate")
    policy_level: PermitPolicyLevel | None = Field(default=None, alias="policyLevel")
    admin_notes: PermitAdminNotes | None = Field(default=None, alias="adminNotes")
    application_list: list[ApplicationOnlineDto] | None = Field(
        default=None, alias="applicationList"
    )
    system_audits: list[SystemAuditItem] | None = Field(default=None, alias="systemAudits")
    allow_t_m_m: bool | None = Field(default=None, alias="allowTMM")
    has_origin_approval_center: bool | None = Field(default=None, alias="hasOriginApprovalCenter")
    response_subject: str | None = Field(default=None, alias="responseSubject")
    response_reason: str | None = Field(default=None, alias="responseReason")
    notify_on_response: bool | None = Field(default=None, alias="notifyOnResponse")
    is_execution_request: bool | None = Field(default=None, alias="isExecutionRequest")


class SystemAuditHealthCenterParams(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    days: int | None = Field(default=None)
    search_text: str | None = Field(default=None, alias="searchText")
    is_logged_in: bool | None = Field(default=None, alias="isLoggedIn")
    after_keys: dict[str, list[Any]] | None = Field(default=None, alias="afterKeys")
    page_size: int | None = Field(default=None, alias="pageSize")
    page_number: int | None = Field(default=None, alias="pageNumber")


class SystemAuditParametersDto(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="allow")
    email_address: str | None = Field(default=None, alias="emailAddress")
    action: str | None = Field(default=None)
    ip_address: str | None = Field(default=None, alias="ipAddress")
    effective_action: str | None = Field(default=None, alias="effectiveAction")
    details: str | None = Field(default=None)
    search_text: str | None = Field(default=None, alias="searchText")
    ip_addresses: list[str] | None = Field(default=None, alias="ipAddresses")
    object_type_ids: list[int] | None = Field(default=None, alias="objectTypeIds")
    start_date: str | None = Field(default=None, alias="startDate")
    end_date: str | None = Field(default=None, alias="endDate")
    page_size: int | None = Field(default=None, alias="pageSize")
    page_number: int | None = Field(default=None, alias="pageNumber")
    view_child_organizations: bool | None = Field(default=None, alias="viewChildOrganizations")
    object_id: str | None = Field(default=None, alias="objectId")
    actions: list[str] | None = Field(default=None)
    index_name: str | None = Field(default=None, alias="indexName")
    after_keys: dict[str, list[Any]] | None = Field(default=None, alias="afterKeys")
    skip_paging: bool | None = Field(default=None, alias="skipPaging")
    function: str | None = Field(default=None)
    page: str | None = Field(default=None)
    email_addresses: list[str] | None = Field(default=None, alias="emailAddresses")


# Resolve any forward references
ActionLogCreatedByProcessesDto.model_rebuild()
Certificate.model_rebuild()
OrganizationParentsDto.model_rebuild()
Int32ObjectKeyValuePair.model_rebuild()
ThreatLockerItemDto.model_rebuild()
EngineRating.model_rebuild()
ActionLogDto.model_rebuild()
ParamsFieldsDto.model_rebuild()
ActionLogParamsDto.model_rebuild()
FilePolicy.model_rebuild()
NetworkPolicy.model_rebuild()
RegistryPolicy.model_rebuild()
AssociatedApplicationPolicy.model_rebuild()
AdvRFPolicy.model_rebuild()
ApplicationFileDto.model_rebuild()
ThreatLockerCertDto.model_rebuild()
ApplicationMatchParameterDto.model_rebuild()
ApplicationOnlineDto.model_rebuild()
ThreatLockerActionDto.model_rebuild()
ApprovalRequestTimerDto.model_rebuild()
ApprovalRequestDto.model_rebuild()
ApprovalRequestParametersDto.model_rebuild()
ApprovalRequestUpdateParametersDto.model_rebuild()
ComputerDataForDisableProtectionDto.model_rebuild()
ComputerDataForEnableProtectionDto.model_rebuild()
ComputerDataForRescanBaselineDto.model_rebuild()
ComputerDataForTransferDto.model_rebuild()
ComputerDataForUpdateModeDto.model_rebuild()
ComputerDisabledProtectionDto.model_rebuild()
ComputerEnableProtectionDto.model_rebuild()
ComputerGroupItemDto.model_rebuild()
ComputerParameterDto.model_rebuild()
ComputerRescanBaselineDto.model_rebuild()
ComputerTransferDto.model_rebuild()
ComputerUpdateDto.model_rebuild()
ComputerUpdateMaintenanceModeDto.model_rebuild()
MaintenanceApplicationDto.model_rebuild()
MaintenanceExistingApplicationDto.model_rebuild()
MaintenanceModeConditionsDto.model_rebuild()
MaintenanceModeEndDto.model_rebuild()
MaintenanceModeInsertDto.model_rebuild()
NetworkExclusionDto.model_rebuild()
PermitAdminNotes.model_rebuild()
PermitFileDetails.model_rebuild()
PermitMatchingApplications.model_rebuild()
PolicyManualOption.model_rebuild()
PermitPolicyConditions.model_rebuild()
PermitPolicyLevel.model_rebuild()
SystemAuditDetails.model_rebuild()
SystemAuditItem.model_rebuild()
PermitApplicationDto.model_rebuild()
SystemAuditHealthCenterParams.model_rebuild()
SystemAuditParametersDto.model_rebuild()
