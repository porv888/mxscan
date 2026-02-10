<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use Illuminate\Http\Request;

class AdminScansController extends Controller
{
    public function index(Request $request)
    {
        $q = Scan::query()
            ->with(['domain:id,domain', 'user:id,name,email'])
            ->when($request->keyword, fn($qr) =>
                $qr->whereHas('domain', fn($d) => $d->where('domain', 'like', "%{$request->keyword}%"))
            )
            ->when($request->status, fn($qr) => $qr->where('status', $request->status))
            ->when($request->type, fn($qr) => $qr->where('type', $request->type))
            ->when($request->score_range, function ($qr) use ($request) {
                match ($request->score_range) {
                    '90-100' => $qr->whereBetween('score', [90, 100]),
                    '70-89' => $qr->whereBetween('score', [70, 89]),
                    '50-69' => $qr->whereBetween('score', [50, 69]),
                    '0-49' => $qr->whereBetween('score', [0, 49]),
                    default => null,
                };
            })
            ->orderBy($request->get('sort', 'created_at'), $request->get('dir', 'desc'));

        $scans = $q->paginate(25)->withQueryString();

        $totalScans = Scan::count();
        $completedScans = Scan::where('status', 'finished')->count();
        $pendingScans = Scan::whereIn('status', ['pending', 'running'])->count();
        $failedScans = Scan::where('status', 'failed')->count();

        return view('admin.scans.index', compact(
            'scans', 'totalScans', 'completedScans', 'pendingScans', 'failedScans'
        ));
    }
}
