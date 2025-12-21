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
        
        if ($used >= $limit) {
            $fail("You have reached your plan's domain limit ({$limit}). Upgrade to add more.");
        }
    }
}
