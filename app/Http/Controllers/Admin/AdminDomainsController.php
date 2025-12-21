<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Domain;
use App\Models\User;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\StreamedResponse;

class AdminDomainsController extends Controller
{
    public function index(Request $request)
    {
        $q = Domain::query()
            ->with(['user:id,name,email'])
            ->select('id','user_id','domain','provider_guess','score_last','last_scanned_at','status')
            ->when($request->keyword, fn($qr) =>
                $qr->where('domain','like',"%{$request->keyword}%")
            )
            ->when($request->status, fn($qr) => $qr->where('status',$request->status))
            ->when($request->blacklist, function($qr) use ($request){
                if ($request->blacklist === 'listed') {
                    $qr->whereHas('scans.blacklistResults', function($q) {
                        $q->where('status', 'listed');
                    });
                } elseif ($request->blacklist === 'clean') {
                    $qr->whereHas('scans.blacklistResults', function($q) {
                        $q->where('status', 'clean');
                    })->whereDoesntHave('scans.blacklistResults', function($q) {
                        $q->where('status', 'listed');
                    });
                } elseif ($request->blacklist === 'unchecked') {
                    $qr->whereDoesntHave('scans.blacklistResults');
                }
            })
            ->orderBy($request->get('sort','last_scanned_at'), $request->get('dir','desc'));

        $domains = $q->paginate(20)->withQueryString();

        return view('admin.domains.index', compact('domains'));
    }

    public function export(Request $request): StreamedResponse
    {
        $file = 'domains_export_'.now()->format('Ymd_His').'.csv';

        $query = Domain::query()->with('user:id,email')->select('id','user_id','domain','score_last','last_scanned_at','status');

        return response()->streamDownload(function() use ($query) {
            $out = fopen('php://output', 'w');
            fputcsv($out, ['ID','Domain','Owner Email','Score','Last Scan','Status','Blacklist']);
            $query->orderBy('id')->chunk(500, function($chunk) use ($out) {
                foreach ($chunk as $d) {
                    fputcsv($out, [$d->id, $d->domain, optional($d->user)->email, $d->score_last, $d->last_scanned_at, $d->status, $d->blacklist_status ?: 'not-checked']);
                }
            });
            fclose($out);
        }, $file, ['Content-Type'=>'text/csv']);
    }

    public function show(Domain $domain)
    {
        $domain->load(['user:id,name,email']);
        // Pull last few scans if you track them
        $recentScans = $domain->scans()->latest()->limit(10)->get(['id','status','score','created_at']);
        return view('admin.domains.show', compact('domain','recentScans'));
    }

    public function update(Request $request, Domain $domain)
    {
        $request->validate([
            'provider_guess' => 'nullable|string|max:255',
            'status'         => 'nullable|string|in:active,pending,paused',
        ]);

        $domain->fill($request->only('provider_guess','status'))->save();

        return back()->with('success','Domain updated');
    }

    public function runScan(Domain $domain)
    {
        // reuse your existing service/job
        // dispatch(new RunScan($domain->id)) or call synchronously if simple
        // For now, pretend:
        // RunScan::dispatchSync($domain->id);
        return back()->with('success','Scan queued/started for '.$domain->domain);
    }

    public function runBlacklist(Domain $domain)
    {
        // dispatch(new RunBlacklistCheck($domain->id));
        return back()->with('success','Blacklist check queued/started for '.$domain->domain);
    }

    public function transfer(Request $request, Domain $domain)
    {
        $request->validate(['new_user_id' => 'required|exists:users,id']);
        $domain->user_id = $request->new_user_id;
        $domain->save();
        return back()->with('success','Ownership transferred');
    }

    public function destroy(Domain $domain)
    {
        $domain->delete();
        return redirect()->route('admin.domains.index')->with('success','Domain deleted');
    }
}
