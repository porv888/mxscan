<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Domain;
use App\Models\Scan;
use App\Models\Subscription;
use App\Models\Invoice;
use App\Models\BlacklistResult;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class AdminController extends Controller
{
    public function __construct()
    {
        $this->middleware(['auth', 'verified']);
        $this->middleware(function ($request, $next) {
            if (!in_array(auth()->user()->role, ['admin', 'superadmin'])) {
                abort(403, 'Access denied. Admin privileges required.');
            }
            return $next($request);
        });
    }

    public function dashboard()
    {
        // Get dashboard statistics
        $totalUsers = User::count();
        $activeSubscriptions = Subscription::where('status', 'active')->count();
        $monthlyRevenue = Invoice::where('status', 'paid')
            ->whereMonth('paid_at', now()->month)
            ->whereYear('paid_at', now()->year)
            ->sum('amount');
        $totalScans = Scan::count();
        
        // Blacklist statistics
        $totalBlacklistChecks = BlacklistResult::count();
        $currentlyBlacklisted = BlacklistResult::where('status', 'listed')
            ->whereHas('scan', function($query) {
                $query->where('created_at', '>=', now()->subDays(7)); // Recent scans only
            })
            ->distinct('ip_address')
            ->count();
        $blacklistProviders = BlacklistResult::distinct('provider')->count();

        // Get recent users (last 5)
        $recentUsers = User::latest()
            ->take(5)
            ->get();

        // Get recent scans (last 5)
        $recentScans = Scan::with(['domain', 'user'])
            ->latest()
            ->take(5)
            ->get();

        return view('admin.dashboard', compact(
            'totalUsers',
            'activeSubscriptions', 
            'monthlyRevenue',
            'totalScans',
            'totalBlacklistChecks',
            'currentlyBlacklisted',
            'blacklistProviders',
            'recentUsers',
            'recentScans'
        ));
    }
}