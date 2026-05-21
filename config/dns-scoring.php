<?php

/**
 * DNS deliverability score weights (must stay in sync with ScannerService).
 */
return [
    'mx' => ['label' => 'MX Records', 'max' => 15],
    'spf' => [
        'label' => 'SPF Record',
        'base' => 15,
        'bonus_strict' => 5,
        'bonus_soft' => 2,
    ],
    'dkim' => ['label' => 'DKIM', 'max' => 15],
    'dmarc' => [
        'label' => 'DMARC',
        'base' => 20,
        'bonus_reject' => 5,
        'bonus_quarantine' => 3,
    ],
    'tlsrpt' => ['label' => 'TLS-RPT', 'max' => 10],
    'mtasts' => [
        'label' => 'MTA-STS',
        'dns_only' => 10,
        'full' => 20,
    ],
    'bimi' => [
        'label' => 'BIMI',
        'valid' => 5,
        'record_only' => 2,
    ],
    'cap' => 100,
];
