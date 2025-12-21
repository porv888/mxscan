<?php

return [
    'product_id' => env('STRIPE_PRODUCT_ID', null),

    // Optional: stable Stripe Price lookup keys you configure in the Stripe Dashboard
    // If provided, the app can resolve these to actual price_ IDs dynamically.
    'lookup_keys' => [
        // monthly
        'premium_monthly' => env('STRIPE_LOOKUP_PREMIUM_MONTHLY'),
        'ultra_monthly'   => env('STRIPE_LOOKUP_ULTRA_MONTHLY'),

        // yearly (optional)
        'premium_yearly'  => env('STRIPE_LOOKUP_PREMIUM_YEARLY'),
        'ultra_yearly'    => env('STRIPE_LOOKUP_ULTRA_YEARLY'),
    ],

    'prices' => [
        // monthly
        'premium_monthly' => env('STRIPE_PRICE_PREMIUM_MONTHLY'),
        'ultra_monthly'   => env('STRIPE_PRICE_ULTRA_MONTHLY'),

        // yearly (optional)
        'premium_yearly'  => env('STRIPE_PRICE_PREMIUM_YEARLY'),
        'ultra_yearly'    => env('STRIPE_PRICE_ULTRA_YEARLY'),
    ],

    'limits' => [
        'freemium' => (int) env('PLAN_LIMIT_FREEMIUM', 1),
        'premium'  => (int) env('PLAN_LIMIT_PREMIUM', 10),
        'ultra'    => (int) env('PLAN_LIMIT_ULTRA', 50),
    ],

    'names' => [
        'freemium' => env('PLAN_NAME_FREEMIUM', 'Freemium'),
        'premium'  => env('PLAN_NAME_PREMIUM',  'Premium'),
        'ultra'    => env('PLAN_NAME_ULTRA',    'Ultra'),
    ],

    'enable_yearly' => filter_var(env('BILLING_ENABLE_YEARLY', false), FILTER_VALIDATE_BOOLEAN),
];
