<?php

namespace App\Services\Entitlement;

/**
 * Account- and domain-level entitlement feature identifiers.
 */
final class EntitlementFeature
{
    public const DOMAIN_CREATE = 'domain_create';
    public const DOMAIN_MANAGE = 'domain_manage';
    public const DOMAIN_ACTIVE = 'domain_active';
    public const MANUAL_FULL_SCAN = 'manual_full_scan';
    public const PARTIAL_SCAN = 'partial_scan';
    public const STANDALONE_TOOLS = 'standalone_tools';
    public const DOMAIN_SPF_ANALYZER = 'domain_spf_analyzer';
    public const AUTOMATIONS = 'automations';
    public const SCHEDULED_SCANS = 'scheduled_scans';
    public const MONITORING = 'monitoring';
    public const DELIVERY_MONITORING = 'delivery_monitoring';
    public const DMARC_ACTIVITY = 'dmarc_activity';
    public const REPORT_EXPORT = 'report_export';
    public const NOTIFICATION_INTEGRATIONS = 'notification_integrations';
    public const API_ACCESS = 'api_access';
    public const EXPIRY_ALERTS = 'expiry_alerts';
}
