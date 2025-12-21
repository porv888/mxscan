<?php

namespace App\Services;

use Illuminate\Support\Facades\Cache;
use Stripe\StripeClient;

class StripePriceResolver
{
    protected StripeClient $stripe;
    protected int $ttlSeconds;

    public function __construct()
    {
        $this->stripe = new StripeClient(config('services.stripe.secret'));
        // Cache for 1 day by default
        $this->ttlSeconds = 60 * 60 * 24;
    }

    /**
     * Resolve a Stripe Price ID (price_...) from a lookup key.
     * Falls back to null if not found.
     */
    public function resolvePriceIdFromLookup(?string $lookupKey): ?string
    {
        $lookupKey = $lookupKey ? trim($lookupKey) : null;
        if (!$lookupKey) {
            return null;
        }

        $cacheKey = "stripe_price_id_for_lookup_{$lookupKey}";
        return Cache::remember($cacheKey, $this->ttlSeconds, function () use ($lookupKey) {
            // List prices by lookup_keys filter (active only)
            $prices = $this->stripe->prices->all([
                'lookup_keys' => [$lookupKey],
                'active' => true,
                'limit' => 1,
            ]);

            $price = $prices->data[0] ?? null;
            return $price?->id ?? null;
        });
    }

    /**
     * Fetch amount and currency for a lookup key for UI display.
     * Returns [amountDecimal, currency] or null if not found.
     */
    public function getAmountCurrencyForLookup(?string $lookupKey): ?array
    {
        $lookupKey = $lookupKey ? trim($lookupKey) : null;
        if (!$lookupKey) {
            return null;
        }

        $cacheKey = "stripe_price_meta_for_lookup_{$lookupKey}";
        return Cache::remember($cacheKey, $this->ttlSeconds, function () use ($lookupKey) {
            $prices = $this->stripe->prices->all([
                'lookup_keys' => [$lookupKey],
                'active' => true,
                'limit' => 1,
            ]);

            $price = $prices->data[0] ?? null;
            if (!$price) return null;

            // unit_amount is in the smallest currency unit (e.g. cents)
            $amountDecimal = isset($price->unit_amount) ? ((int)$price->unit_amount) / 100 : null;
            $currency = $price->currency ?? null;

            return ($amountDecimal !== null && $currency)
                ? [$amountDecimal, strtoupper($currency)]
                : null;
        });
    }
}
