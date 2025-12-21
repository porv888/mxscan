<?php

namespace App\Http\Controllers;

use App\Models\Domain;
use App\Models\DeliveryMonitor;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class DomainSettingsController extends Controller
{
    /**
     * Update enabled services for a domain.
     */
    public function updateServices(Request $request, Domain $domain)
    {
        // Ensure user owns this domain
        if ($domain->user_id !== $request->user()->id) {
            abort(403, 'Unauthorized access to domain.');
        }

        $data = $request->validate([
            'services' => 'array',
            'services.*' => 'string'
        ]);

        $sched = $domain->schedules()->latest('id')->first();
        if (!$sched) {
            return back()->with('error', 'No schedule found for this domain.');
        }

        $settings = $sched->settings ?? [];
        $newServices = collect($data['services'] ?? [])
            ->values()
            ->unique()
            ->intersect(['dns', 'blacklist', 'spf', 'delivery'])
            ->all();

        $oldServices = $settings['services'] ?? [];
        $settings['services'] = $newServices;
        $sched->settings = $settings;
        $sched->save();

        // Handle delivery monitor creation/deletion
        $hadDelivery = in_array('delivery', $oldServices, true);
        $hasDelivery = in_array('delivery', $newServices, true);

        if (!$hadDelivery && $hasDelivery) {
            // Create delivery monitor
            $token = Str::uuid()->toString();
            $local = 'monitor+' . $token;
            $addr = $local . '@mxscan.me';

            DeliveryMonitor::create([
                'user_id' => $request->user()->id,
                'domain_id' => $domain->id,
                'label' => $domain->domain . ' monitor',
                'inbox_address' => $addr,
                'token' => $token,
                'status' => 'active',
                'last_check_at' => null,
                'last_incident_notified_at' => null,
            ]);
        } elseif ($hadDelivery && !$hasDelivery) {
            // Optionally pause or delete delivery monitor
            DeliveryMonitor::where('domain_id', $domain->id)->update(['status' => 'paused']);
        }

        return back()->with('success', 'Services updated successfully.');
    }

    /**
     * Update scan cadence for a domain.
     */
    public function updateCadence(Request $request, Domain $domain)
    {
        // Ensure user owns this domain
        if ($domain->user_id !== $request->user()->id) {
            abort(403, 'Unauthorized access to domain.');
        }

        $data = $request->validate([
            'cadence' => 'required|string'
        ]);

        [$cad, $at] = str_contains($data['cadence'], '@') 
            ? explode('@', $data['cadence'], 2) 
            : [$data['cadence'], null];
        
        $cad = in_array($cad, ['off', 'daily', 'weekly'], true) ? $cad : 'off';

        $sched = $domain->schedules()->latest('id')->first();
        if (!$sched) {
            return back()->with('error', 'No schedule found for this domain.');
        }

        $sched->status = ($cad === 'off') ? 'paused' : 'active';
        $sched->frequency = ($cad === 'off') ? 'daily' : $cad; // enum requires a value
        
        $settings = $sched->settings ?? [];
        $settings['run_at'] = $at && preg_match('/^\d{2}:\d{2}$/', $at) ? ($at . ':00') : null;
        $sched->settings = $settings;
        $sched->save();

        $message = $cad === 'off' 
            ? 'Automatic scans disabled.' 
            : "Scans scheduled {$cad}" . ($at ? " at {$at} UTC" : '');

        return back()->with('success', $message);
    }
}
