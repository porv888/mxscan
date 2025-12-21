<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\Domain;
use App\Models\Scan;

class DashboardController extends Controller
{
    /**
     * Create a new controller instance.
     */
    public function __construct()
    {
        $this->middleware('auth');
    }

    /**
     * Show the application dashboard.
     */
    public function index()
    {
        \Log::info('Dashboard accessed', [
            'user_id' => Auth::id(),
            'authenticated' => Auth::check(),
            'session_id' => session()->getId()
        ]);
        
        $user = Auth::user();

        // Get total domains count
        $totalDomains = $user->domains()->count();

        // Get last scan date from domains
        $lastScanDomain = $user->domains()
            ->whereNotNull('last_scanned_at')
            ->orderByDesc('last_scanned_at')
            ->first();
        
        $lastScanDate = $lastScanDomain ? $lastScanDomain->last_scanned_at : null;

        // Get average security score
        $averageScore = $user->domains()
            ->whereNotNull('score_last')
            ->avg('score_last');

        // Get recent scans
        $recentScans = Scan::with('domain')
            ->whereHas('domain', function ($query) use ($user) {
                $query->where('user_id', $user->id);
            })
            ->latest()
            ->take(5)
            ->get();

        // Get domains with relationships for blacklist widget
        $domains = $user->domains()->with(['activeSchedule', 'scans' => function($query) {
            $query->whereHas('blacklistResults')->latest()->take(1);
        }])->get();

        return view('dashboard.index', compact(
            'totalDomains',
            'lastScanDate',
            'averageScore',
            'recentScans',
            'domains'
        ));
    }
}
