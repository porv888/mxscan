<?php

/**
 * Email Security Score weights (authentication and transport-security configuration).
 *
 * Historical scans may have been scored with the previous deliverability model
 * (different component weights and BIMI deductions). Stored scan.score values
 * are not recalculated; only new scans use this model.
 *
 * Must stay in sync with ScannerService and ScoreBreakdownService.
 */
return [
    'mx' => ['label' => 'MX Records', 'max' => 15],
    'spf' => [
        'label' => 'SPF Record',
        'base' => 20,
        'bonus_strict' => 0,
        'bonus_soft' => 0,
    ],
    'dkim' => ['label' => 'DKIM DNS configuration', 'max' => 20],
    // DMARC keeps its 30-point weight while attributing policy and reporting separately.
    'dmarc' => [
        'label' => 'DMARC',
        'base' => 30,
        'policy_max' => 24,
        'reporting_max' => 6,
        'bonus_reject' => 0,
        'bonus_quarantine' => 0,
    ],
    'tlsrpt' => ['label' => 'TLS-RPT', 'max' => 5],
    'mtasts' => [
        'label' => 'MTA-STS',
        'max' => 10,
    ],
    'bimi' => [
        'label' => 'BIMI',
        'valid' => 0,
        'record_only' => 0,
        'optional' => true,
    ],
    'cap' => 100,
];
