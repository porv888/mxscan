<?php

return [
    'senders' => [
        'google' => [
            'name' => 'Google Workspace',
            'include' => '_spf.google.com',
            'dkim_selectors' => ['google'],
            'dkim_steps' => ['Open Google Admin Console.', 'Go to Apps → Google Workspace → Gmail → Authenticate email.', 'Generate and publish the DKIM record, then start authentication.'],
        ],
        'microsoft' => [
            'name' => 'Microsoft 365',
            'include' => 'spf.protection.outlook.com',
            'dkim_selectors' => ['selector1', 'selector2'],
            'dkim_steps' => ['Open the Microsoft Defender portal.', 'Go to Email & collaboration → Policies & rules → Threat policies → DKIM.', 'Select the domain, publish both CNAME records, then enable signing.'],
        ],
        'mailchimp' => [
            'name' => 'Mailchimp',
            'include' => 'spf.mandrillapp.com',
            'dkim_selectors' => ['k1', 'k2', 'k3', 'mte1', 'mte2', 'mandrill'],
        ],
        'sendgrid' => [
            'name' => 'SendGrid',
            'include' => 'sendgrid.net',
            'dkim_selectors' => ['sendgrid', 'smtpapi'],
        ],
        'brevo' => [
            'name' => 'Brevo',
            'include' => 'sendinblue.com',
            'dkim_selectors' => [],
        ],
        'amazonses' => [
            'name' => 'Amazon SES',
            'include' => 'amazonses.com',
            'dkim_selectors' => ['amazonses'],
        ],
        'mailgun' => [
            'name' => 'Mailgun',
            'include' => 'mailgun.org',
            'dkim_selectors' => ['mailgun'],
        ],
    ],

    'dns_providers' => [
        'cloudflare' => ['name' => 'Cloudflare', 'steps' => ['Open DNS.', 'Click Add record.', 'Select TXT.', 'Enter the generated host and value.', 'Set TTL to Auto and save.']],
        'godaddy' => ['name' => 'GoDaddy', 'steps' => ['Open the domain portfolio.', 'Open DNS for the domain.', 'Click Add New Record and select TXT.', 'Enter the generated host and value.', 'Save the record.']],
        'namecheap' => ['name' => 'Namecheap', 'steps' => ['Open Domain List → Manage.', 'Open Advanced DNS.', 'Add a TXT Record.', 'Enter the generated host and value.', 'Save all changes.']],
        'route53' => ['name' => 'Route 53', 'steps' => ['Open the hosted zone.', 'Click Create record.', 'Enter the generated record name.', 'Select TXT and paste the generated value.', 'Create the record.']],
        'google_cloud_dns' => ['name' => 'Google Cloud DNS', 'steps' => ['Open the managed zone.', 'Click Add standard.', 'Enter the generated DNS name.', 'Select TXT and paste the generated value.', 'Create the record set.']],
        'cpanel' => ['name' => 'cPanel', 'steps' => ['Open Zone Editor.', 'Click Manage for the domain.', 'Click Add Record and select TXT.', 'Enter the generated host and value.', 'Save Record.']],
        'other' => ['name' => 'Other', 'steps' => ['Open your DNS provider’s record editor.', 'Create a TXT record.', 'Enter the generated host and value.', 'Use Auto or 3600 for TTL.', 'Save the record.']],
    ],
];
