<?php

return [
    /*
    |--------------------------------------------------------------------------
    | TTI (Time-to-Inbox) Threshold
    |--------------------------------------------------------------------------
    |
    | The threshold in minutes for considering TTI as "slow". Incidents will
    | be created when TTI exceeds this value.
    |
    */
    'tti_slow_minutes' => env('TTI_SLOW_MINUTES', 30),

    /*
    |--------------------------------------------------------------------------
    | Data Retention Settings
    |--------------------------------------------------------------------------
    |
    | Configure how long to retain various types of data.
    |
    */
    'retention' => [
        'raw_body_days' => env('RAW_BODY_RETENTION_DAYS', 30),
    ],
];
