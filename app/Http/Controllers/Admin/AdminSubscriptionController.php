<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Plan;
use App\Models\Subscription;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\StreamedResponse;

class AdminSubscriptionController extends Controller
{
    public function index(Request $request)
    {
        $status  = $request->get('status');       // active, canceled, trialing, past_due
        $planId  = $request->get('plan_id');      // plan filter
        $search  = $request->get('q');            // email / name search
        $from    = $request->get('from');         // date range start (started_at)
        $to      = $request->get('to');           // date range end

        $plans = Plan::where('active', 1)->orderBy('domain_limit')->get();

        $subs = Subscription::with(['user','plan'])
            ->when($status, fn($q) => $q->where('status', $status))
            ->when($planId, fn($q) => $q->where('plan_id', $planId))
            ->when($search, function($q) use ($search) {
                $q->whereHas('user', function($uq) use ($search) {
                    $uq->where('email', 'like', "%{$search}%")
                       ->orWhere('name', 'like', "%{$search}%");
                });
            })
            ->when($from, fn($q) => $q->whereDate('started_at', '>=', $from))
            ->when($to,   fn($q) => $q->whereDate('started_at', '<=', $to))
            ->latest('started_at')
            ->paginate(20)
            ->withQueryString();

        // KPI cards
        $kpi = [
            'active'   => Subscription::where('status','active')->count(),
            'trialing' => Subscription::whereIn('status', ['trialing', 'trial'])->count(),
            'canceled' => Subscription::where('status','canceled')->count(),
            'mrr'      => (float) Subscription::where('status','active')->with('plan')->get()->sum(fn($s)=> $s->plan?->price ?? 0),
        ];

        return view('admin.subscriptions.index', compact('subs','plans','kpi','status','planId','search','from','to'));
    }

    public function show(Subscription $subscription)
    {
        $subscription->load(['user','plan']);
        $plans = Plan::where('active',1)->orderBy('domain_limit')->get();

        // computed usage
        $used  = $subscription->user->domains()->count();
        $limit = (int) optional($subscription->plan)->domain_limit ?: 1;

        return view('admin.subscriptions.show', compact('subscription','plans','used','limit'));
    }

    public function update(Request $request, Subscription $subscription)
    {
        $request->validate([
            'plan_id'   => ['nullable','exists:plans,id'],
            'status'    => ['required','in:active,canceled,trialing,trial,past_due'],
            'renews_at' => ['nullable','date'],
            'notes'     => ['nullable','string','max:1000'],
        ]);

        // if changing plan, prevent forcing a plan under the user's current usage
        if ($request->filled('plan_id')) {
            $newPlan = Plan::find($request->plan_id);
            $used    = $subscription->user->domains()->count();
            if ($newPlan && $used > $newPlan->domain_limit) {
                return back()->withErrors([
                    'plan_id' => "User has {$used} domains; plan '{$newPlan->name}' allows {$newPlan->domain_limit}.",
                ]);
            }
            $subscription->plan()->associate($newPlan);
        }

        $subscription->status    = $request->status;
        $subscription->renews_at = $request->renews_at ? now()->parse($request->renews_at) : null;
        $subscription->notes     = $request->notes;

        // handle canceled_at timestamp
        if ($request->status === 'canceled' && !$subscription->canceled_at) {
            $subscription->canceled_at = now();
        }
        if ($request->status !== 'canceled') {
            $subscription->canceled_at = null;
        }

        $subscription->save();

        // audit log
        $this->audit("admin.updated_subscription", [
            'subscription_id' => $subscription->id,
            'admin_id' => $request->user()->id,
            'changes' => $request->only(['plan_id','status','renews_at','notes']),
        ]);

        return redirect()->route('admin.subscriptions.show', $subscription)->with('success','Subscription updated.');
    }

    public function cancel(Request $request, Subscription $subscription)
    {
        $subscription->status = 'canceled';
        $subscription->canceled_at = now();
        $subscription->save();

        $this->audit("admin.canceled_subscription", [
            'subscription_id' => $subscription->id,
            'admin_id' => $request->user()->id,
        ]);

        return back()->with('success', 'Subscription canceled.');
    }

    public function resume(Request $request, Subscription $subscription)
    {
        $subscription->status = 'active';
        $subscription->canceled_at = null;
        $subscription->renews_at = now()->addMonth();
        $subscription->save();

        $this->audit("admin.resumed_subscription", [
            'subscription_id' => $subscription->id,
            'admin_id' => $request->user()->id,
        ]);

        return back()->with('success', 'Subscription resumed.');
    }

    public function export(Request $request): StreamedResponse
    {
        $fileName = 'subscriptions_export_' . now()->format('Ymd_His') . '.csv';

        $query = Subscription::with(['user','plan'])
            ->when($request->get('status'), fn($q,$v)=>$q->where('status',$v))
            ->when($request->get('plan_id'), fn($q,$v)=>$q->where('plan_id',$v))
            ->when($request->get('q'), function($q) use ($request) {
                $search = $request->get('q');
                $q->whereHas('user', function($uq) use ($search) {
                    $uq->where('email', 'like', "%{$search}%")
                       ->orWhere('name', 'like', "%{$search}%");
                });
            })
            ->when($request->get('from'), fn($q,$v)=>$q->whereDate('started_at', '>=', $v))
            ->when($request->get('to'), fn($q,$v)=>$q->whereDate('started_at', '<=', $v));

        $headers = [
            'Content-Type' => 'text/csv',
            'Content-Disposition' => "attachment; filename=\"$fileName\"",
        ];

        return response()->stream(function() use ($query) {
            $out = fopen('php://output', 'w');
            fputcsv($out, ['ID','User','Email','Plan','Price','Status','Started','Renews','Canceled','Domains Used']);

            $query->chunk(500, function($rows) use ($out) {
                foreach($rows as $s) {
                    $used = $s->user ? $s->user->domains()->count() : 0;
                    fputcsv($out, [
                        $s->id,
                        optional($s->user)->name,
                        optional($s->user)->email,
                        optional($s->plan)->name,
                        optional($s->plan)->price,
                        $s->status,
                        optional($s->started_at)?->toDateString(),
                        optional($s->renews_at)?->toDateString(),
                        optional($s->canceled_at)?->toDateString(),
                        $used,
                    ]);
                }
            });

            fclose($out);
        }, 200, $headers);
    }

    protected function audit(string $event, array $data): void
    {
        // If you have an audit_logs table:
        try {
            DB::table('audit_logs')->insert([
                'event' => $event,
                'data'  => json_encode($data),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (\Throwable $e) {
            // swallow in case table not present
        }
    }
}
