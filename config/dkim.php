<?php

return [
    'selectors' => [
        'google',                           // Google Workspace
        'selector1', 'selector2',           // Microsoft 365
        'k1', 'k2', 'k3',                  // Mailchimp / Mandrill
        'mte1', 'mte2',                    // Mandrill (transactional)
        'default', 'mail', 'dkim',          // Generic
        's1', 's2',                         // Generic
        'smtp', 'email',                    // Generic
        'protonmail', 'protonmail2', 'protonmail3', // Proton Mail
        'sendgrid', 'smtpapi',              // SendGrid
        'mailgun',                          // Mailgun
        'amazonses',                        // AWS SES
        'postmark',                         // Postmark
        'cm',                               // Campaign Monitor
        'turbo-smtp',                       // TurboSMTP
        'mxvault',                          // MXVault
        'fm1', 'fm2', 'fm3',               // Fastmail
        'mandrill',                         // Mandrill
        'zendesk1', 'zendesk2',             // Zendesk
        'everlytickey1', 'everlytickey2',   // Everlytic
        'dkim1024',                         // Generic 1024
    ],

    'provider_selectors' => [
        'Google Workspace' => ['google'],
        'Microsoft 365' => ['selector1', 'selector2'],
        'ProtonMail' => ['protonmail', 'protonmail2', 'protonmail3'],
        'FastMail' => ['fm1', 'fm2', 'fm3'],
        'Zoho Mail' => ['zoho', 'zmail'],
    ],

    'catalog_limit' => 25,
    'max_selectors_per_scan' => 30,
    'cname_max_depth' => 5,
    'resolver_timeout_ms' => 5000,
];
