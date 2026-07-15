<?php

return [
    /*
    |--------------------------------------------------------------------------
    | SPF evaluation engine
    |--------------------------------------------------------------------------
    |
    | legacy — App\Services\Spf\SpfResolver (Phase 1 behaviour)
    | native — App\Domain\EmailSecurity\Checks\SPF\SpfCheck
    |
    */
    'spf_engine' => env('EMAIL_SECURITY_SPF_ENGINE', 'legacy'),

    /*
    |--------------------------------------------------------------------------
    | Expected MXScan TLS-RPT reporting destination (mailto)
    |--------------------------------------------------------------------------
    */
    'tls_rpt_expected_mailto' => env('EMAIL_SECURITY_TLS_RPT_EXPECTED_MAILTO', 'tls-reports@mxscan.me'),

    /*
    |--------------------------------------------------------------------------
    | Native certificate monitoring
    |--------------------------------------------------------------------------
    */
    'certificates' => [
        'connect_timeout_seconds' => (int) env('EMAIL_SECURITY_CERTIFICATES_CONNECT_TIMEOUT', 8),
        'max_endpoints_per_scan' => (int) env('EMAIL_SECURITY_CERTIFICATES_MAX_ENDPOINTS', 10),
        'expiry_warning_days' => (int) env('EMAIL_SECURITY_CERTIFICATES_EXPIRY_WARNING_DAYS', 30),
        'expiry_critical_days' => (int) env('EMAIL_SECURITY_CERTIFICATES_EXPIRY_CRITICAL_DAYS', 14),
        'expiry_urgent_days' => (int) env('EMAIL_SECURITY_CERTIFICATES_EXPIRY_URGENT_DAYS', 7),
        'alert_thresholds_days' => [30, 14, 7, 0],
    ],
];
