<?php

return [
    /*
    |--------------------------------------------------------------------------
    | SPF evaluation engine
    |--------------------------------------------------------------------------
    |
    | legacy — App\Services\Spf\SpfResolver (Phase 1 behaviour)
    | native — App\Domain\EmailSecurity\Checks\SPF\SpfCheck
    |
    */
    'spf_engine' => env('EMAIL_SECURITY_SPF_ENGINE', 'legacy'),
];
