<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Expiry Detection Configuration
    |--------------------------------------------------------------------------
    |
    | Multi-source domain and SSL expiry detection with resilient fallbacks.
    |
    */

    'enabled' => env('EXPIRY_ENABLE', true),

    /*
    |--------------------------------------------------------------------------
    | Domain Expiry Providers
    |--------------------------------------------------------------------------
    */

    'domain' => [
        'rdap' => [
            'enabled' => env('EXPIRY_RDAP_ENABLE', true),
            'aggregator_enabled' => env('EXPIRY_RDAP_AGG_ENABLE', true),
            'aggregator_url' => env('EXPIRY_RDAP_AGG_URL', 'https://rdap.org/domain'),
        ],

        'whois_api' => [
            'enabled' => env('EXPIRY_WHOIS_API_ENABLE', false),
            'provider' => env('WHOIS_API_PROVIDER', 'whoisxmlapi'), // whoisxmlapi | jsonwhois | ip2whois | whoisfreaks
        ],
        
        'tcp_whois' => [
            'enabled' => env('EXPIRY_TCP_WHOIS_ENABLE', true), // Enabled by default
        ],
        
        'whois_binary' => [
            'enabled' => env('EXPIRY_WHOIS_BINARY', false),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | SSL Expiry Providers
    |--------------------------------------------------------------------------
    */

    'ssl' => [
        'live_tls' => [
            'enabled' => env('EXPIRY_SSL_LIVE_ENABLE', true),
            'hostnames' => ['%domain%', 'www.%domain%'], // %domain% will be replaced
        ],

        'ct' => [
            'enabled' => env('EXPIRY_SSL_CT_ENABLE', false),
            'certspotter_token' => env('CERTSPOTTER_TOKEN'),
            'crtsh_enabled' => env('CRT_SH_ENABLE', false),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Timeouts & Limits
    |--------------------------------------------------------------------------
    */

    'http_timeout' => env('EXPIRY_HTTP_TIMEOUT', 8),
    'connect_timeout' => env('EXPIRY_CONNECT_TIMEOUT', 8),
    'retry_backoff' => env('EXPIRY_RETRY_BACKOFF', 300), // seconds

    /*
    |--------------------------------------------------------------------------
    | Job Scheduling
    |--------------------------------------------------------------------------
    */

    'daily_at' => env('EXPIRY_DAILY_AT', '03:10'),
    'alert_thresholds' => array_map('intval', explode(',', env('EXPIRY_ALERT_THRESHOLDS', '30,14,7,3,1'))),

    /*
    |--------------------------------------------------------------------------
    | Behavior
    |--------------------------------------------------------------------------
    */

    'allow_overwrite' => env('EXPIRY_ALLOW_OVERWRITE', true),
    'chunk_size_ssl' => env('EXPIRY_CHUNK_SIZE_SSL', 200),
    'chunk_size_domain' => env('EXPIRY_CHUNK_SIZE_DOMAIN', 100),
];
