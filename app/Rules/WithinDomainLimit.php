<?php

namespace App\Rules;

use App\Services\Entitlement\EntitlementService;
use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

class WithinDomainLimit implements ValidationRule
{
    public function __construct(protected $user)
    {
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $entitlements = app(EntitlementService::class);
        $limit = $entitlements->domainLimit($this->user);
        $used = $entitlements->domainsUsed($this->user);

        if ($used < $limit) {
            return;
        }

        if ($limit <= 1) {
            $fail('Your Free plan supports 1 domain. Upgrade to add more.');
            return;
        }

        $fail("You have reached your plan's domain limit ({$limit}). Upgrade to add more.");
    }
}
