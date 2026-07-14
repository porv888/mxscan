<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use App\Http\Controllers\Controller;
use App\Services\Entitlement\EntitlementFeature;
use App\Services\Entitlement\EntitlementService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Redirect;

class DomainActionsController extends Controller
{
    public function __construct(
        protected EntitlementService $entitlements
    ) {
    }

    public function runScan(Request $request, Domain $domain)
    {
        // Trigger scan for the domain
        // This would integrate with your scanning logic
        
        return Redirect::route('domains.hub', $domain)->with('success', 'Scan started for ' . $domain->name);
    }
    
    public function runBlacklist(Request $request, Domain $domain)
    {
        if (!$this->entitlements->canOnDomain($request->user(), $domain, EntitlementFeature::PARTIAL_SCAN)) {
            return $this->entitlements->deny($request, EntitlementFeature::PARTIAL_SCAN);
        }

        return Redirect::route('domains.hub', $domain)->with('success', 'Blacklist check started for ' . $domain->name);
    }
    
    public function downloadFixPack(Request $request, Domain $domain)
    {
        if (!$this->entitlements->can($request->user(), EntitlementFeature::STANDALONE_TOOLS)) {
            return $this->entitlements->deny($request, EntitlementFeature::STANDALONE_TOOLS);
        }

        return Redirect::route('domains.hub', $domain)->with('info', 'Fix pack generation not yet implemented');
    }
}