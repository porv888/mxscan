<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

class WithinDomainLimit implements ValidationRule
{
    protected $user;

    public function __construct($user)
    {
        $this->user = $user;
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        $limit = $this->user->domainLimit();
        $used = $this->user->domainsUsed();
        
        // If under limit, always allow
        if ($used < $limit) {
            return;
        }
        
        // At or over limit - check if this is a subdomain of an existing domain
        // or if an existing domain is a subdomain of this one (same organizational domain)
        $newDomain = strtolower(trim($value));
        $existingDomains = $this->user->domains()->pluck('domain')->map(fn($d) => strtolower($d));
        
        foreach ($existingDomains as $existing) {
            // New domain is subdomain of existing (e.g., adding app.domain.com when domain.com exists)
            if (str_ends_with($newDomain, '.' . $existing)) {
                return;
            }
            // Existing domain is subdomain of new (e.g., adding domain.com when app.domain.com exists)
            if (str_ends_with($existing, '.' . $newDomain)) {
                return;
            }
        }
        
        $fail("You have reached your plan's domain limit ({$limit}). Upgrade to add more.");
    }
}
