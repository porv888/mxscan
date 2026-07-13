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
    'dmarc' => [
        'label' => 'DMARC',
        'base' => 30,
        'bonus_reject' => 0,
        'bonus_quarantine' => 0,
    ],
    'tlsrpt' => ['label' => 'TLS-RPT', 'max' => 5],
    'mtasts' => [
        'label' => 'MTA-STS',
        'dns_only' => 5,
        'full' => 10,
    ],
    'bimi' => [
        'label' => 'BIMI',
        'valid' => 0,
        'record_only' => 0,
        'optional' => true,
    ],
    'cap' => 100,
];
