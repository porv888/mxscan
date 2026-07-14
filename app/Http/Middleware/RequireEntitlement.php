<?php

namespace App\Http\Middleware;

use App\Models\Domain;
use App\Services\Entitlement\EntitlementFeature;
use App\Services\Entitlement\EntitlementService;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireEntitlement
{
    public function __construct(
        protected EntitlementService $entitlements
    ) {
    }

    public function handle(Request $request, Closure $next, string $feature): Response
    {
        $user = $request->user();
        if (!$user) {
            abort(401);
        }

        $domain = $request->route('domain');
        if ($domain instanceof Domain) {
            if (!$this->entitlements->canOnDomain($user, $domain, $feature)) {
                return $this->entitlements->deny($request, $feature);
            }

            return $next($request);
        }

        if (!$this->entitlements->can($user, $feature)) {
            return $this->entitlements->deny($request, $feature);
        }

        return $next($request);
    }
}
