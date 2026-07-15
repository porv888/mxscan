<?php

return [
    'standards_profile' => [
        'core' => 'draft-brand-indicators-for-message-identification-14',
        'svg' => 'svg-tiny-ps-current',
        'mark_certificate' => 'current',
        'vmc_fetch_validation' => 'current-draft',
    ],

    'svg_max_bytes' => (int) env('BIMI_SVG_MAX_BYTES', 32768),
    'svg_max_elements' => 500,
    'svg_max_depth' => 32,

    'fetch' => [
        'connect_timeout_seconds' => 5,
        'response_timeout_seconds' => 10,
        'max_download_bytes' => 65536,
        'max_decompressed_bytes' => 131072,
        'allow_redirects' => false,
        'allowed_port' => 443,
    ],

    'mark_certificate' => [
        'max_pem_bytes' => 1048576,
        'max_certificates' => 10,
        'expiry_warning_days' => 30,
    ],

    'dmarc_core' => [
        'min_policy' => 'quarantine',
        'require_pct_100' => true,
    ],

    'preview' => [
        'disk' => 'local',
        'path_prefix' => 'private/bimi-indicators',
        'max_raster_dimension' => 256,
        'cache_ttl_seconds' => 3600,
    ],

    'provider_profiles' => [
        'self_asserted_capable' => [
            'label' => 'Self-asserted capable',
            'dmarc' => ['core_eligible' => true],
            'certificate' => ['required' => false],
            'svg' => ['tiny_ps_required' => true],
            'display' => ['guaranteed' => false],
        ],
        'mark_certificate_required' => [
            'label' => 'Mark Certificate required',
            'dmarc' => ['core_eligible' => true],
            'certificate' => ['required' => true, 'types' => ['vmc', 'cmc', 'unknown']],
            'svg' => ['tiny_ps_required' => true],
            'display' => ['guaranteed' => false],
        ],
        'vmc_required' => [
            'label' => 'VMC required',
            'dmarc' => ['core_eligible' => true],
            'certificate' => ['required' => true, 'types' => ['vmc']],
            'svg' => ['tiny_ps_required' => true],
            'display' => ['guaranteed' => false],
        ],
        'vmc_or_cmc_supported' => [
            'label' => 'VMC or CMC supported',
            'dmarc' => ['core_eligible' => true],
            'certificate' => ['required' => true, 'types' => ['vmc', 'cmc']],
            'svg' => ['tiny_ps_required' => true],
            'display' => ['guaranteed' => false],
        ],
    ],
];
