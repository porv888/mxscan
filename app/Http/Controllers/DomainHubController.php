<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use Illuminate\Http\Request;

class DomainHubController extends Controller
{
    public function overview(Domain $domain)
    {
        $this->authorize('view', $domain);
        
        $latestScan = $domain->scans()->latest()->first();
        
        // Load schedule settings to determine enabled services
        $sched = $domain->schedules()->latest('id')->first();
        $settings = is_array($sched?->settings) ? $sched->settings : [];
        
        // Determine enabled services (default to dns, blacklist, spf if not set)
        $enabled = collect($settings['services'] ?? ['dns', 'blacklist', 'spf'])
            ->intersect(['dns', 'blacklist', 'spf', 'delivery'])
            ->flip()
            ->map(fn() => true)
            ->all();
        
        // Determine cadence
        $cadence = $sched?->status === 'active' ? ($sched->frequency ?? 'daily') : 'off';
        $runAt = $settings['run_at'] ?? null;
        
        return view('domains.hub.overview', compact('domain', 'latestScan', 'enabled', 'cadence', 'runAt'));
    }

    public function history(Domain $domain)
    {
        $this->authorize('view', $domain);
        $scans = $domain->scans()->latest()->paginate(20);
        return view('domains.hub.history', compact('domain', 'scans'));
    }

    public function schedules(Domain $domain)
    {
        $this->authorize('view', $domain);
        $schedules = $domain->schedules()->latest()->get();
        return view('domains.hub.schedules', compact('domain', 'schedules'));
    }

    public function tools(Domain $domain)
    {
        $this->authorize('view', $domain);
        return view('domains.hub.tools', compact('domain'));
    }

    public function settings(Domain $domain)
    {
        $this->authorize('update', $domain);
        
        // Load schedule settings
        $sched = $domain->schedules()->latest('id')->first();
        $settings = is_array($sched?->settings) ? $sched->settings : [];
        
        // Determine enabled services
        $enabled = collect($settings['services'] ?? ['dns', 'blacklist', 'spf'])
            ->intersect(['dns', 'blacklist', 'spf', 'delivery'])
            ->flip()
            ->map(fn() => true)
            ->all();
        
        // Determine cadence
        $cadence = $sched?->status === 'active' ? ($sched->frequency ?? 'daily') : 'off';
        $runAt = $settings['run_at'] ?? null;
        
        return view('domains.hub.settings', compact('domain', 'enabled', 'cadence', 'runAt'));
    }
}