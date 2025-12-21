<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    /**
     * The URIs that should be excluded from CSRF verification.
     *
     * We exclude Stripe webhooks to avoid CSRF errors when Stripe posts events.
     */
    protected $except = [
        'stripe/*', // e.g. /stripe/webhook
        'stripe/webhook', // Explicit exemption for webhook endpoint
    ];
}
