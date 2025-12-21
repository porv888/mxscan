<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Subscription;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

class SubscriptionsController extends Controller
{
    public function index(Request $request)
    {
        $q = Subscription::query()
            ->with(['user:id,name,email','plan:id,name,price'])
            ->select('id','user_id','plan_id','status','expires_at','canceled_at','created_at')
            ->when($request->keyword, function($qr) use ($request) {
                $qr->whereHas('user', fn($u)=>$u->where('email','like',"%{$request->keyword}%"));
            })
            ->when($request->status, fn($qr)=>$qr->where('status',$request->status))
            ->orderBy($request->get('sort','created_at'), $request->get('dir','desc'));

        $subs = $q->paginate(20)->withQueryString();

        // Simple metrics tiles (optional)
        $mrr   = Subscription::where('status','active')->with('plan:id,price')->get()->sum(fn($s)=> (float) optional($s->plan)->price);
        $active= Subscription::where('status','active')->count();
        $canceled = Subscription::where('status','canceled')->count();

        return view('admin.subscriptions.index', compact('subs','mrr','active','canceled'));
    }

    public function export(): StreamedResponse
    {
        $file = 'subscriptions_export_'.now()->format('Ymd_His').'.csv';
        $query = Subscription::query()->with(['user:id,email','plan:id,name,price'])
            ->select('id','user_id','plan_id','status','expires_at','canceled_at','created_at');

        return response()->streamDownload(function() use ($query) {
            $out = fopen('php://output', 'w');
            fputcsv($out, ['ID','User Email','Plan','Price','Status','Expires','Canceled','Created']);
            $query->orderBy('id')->chunk(500, function($chunk) use ($out) {
                foreach ($chunk as $s) {
                    fputcsv($out, [
                        $s->id,
                        optional($s->user)->email,
                        optional($s->plan)->name,
                        optional($s->plan)->price,
                        $s->status,
                        $s->expires_at,
                        $s->canceled_at,
                        $s->created_at,
                    ]);
                }
            });
            fclose($out);
        }, $file, ['Content-Type'=>'text/csv']);
    }

    public function show(Subscription $subscription)
    {
        $subscription->load(['user:id,name,email','plan:id,name,price']);
        return view('admin.subscriptions.show', compact('subscription'));
    }

    public function cancel(Subscription $subscription)
    {
        $subscription->status = 'canceled';
        $subscription->canceled_at = now();
        $subscription->save();
        return back()->with('success','Subscription canceled');
    }

    public function resume(Subscription $subscription)
    {
        $subscription->status = 'active';
        $subscription->canceled_at = null;
        $subscription->save();
        return back()->with('success','Subscription resumed');
    }
}
