<?php

return [
    'imap' => [
        'host'       => env('IMAP_HOST'),
        'port'       => (int) env('IMAP_PORT', 993),
        'encryption' => env('IMAP_ENCRYPTION', 'ssl'),
        'username'   => env('IMAP_USERNAME'),
        'password'   => env('IMAP_PASSWORD'),
        'folder'     => env('IMAP_FOLDER', 'INBOX'),
    ],
    'tti_threshold_ms' => (int) env('MONITOR_TTI_THRESHOLD_MS', 15 * 60 * 1000),
    'from_hint'        => env('MONITOR_FROM_HINT', ''), // optional filter
    'max_age_hours'    => (int) env('MONITOR_MAX_AGE_HOURS', 48),
    
    // Plan limits
    'limits' => [
        'freemium' => (int) env('MONITOR_LIMIT_FREEMIUM', 1),
        'premium'  => (int) env('MONITOR_LIMIT_PREMIUM', 10),
        'ultra'    => (int) env('MONITOR_LIMIT_ULTRA', 50),
    ],
];
