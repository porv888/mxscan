@props(['timeframe' => '30'])

@php
    use App\Models\BlacklistResult;
    use App\Models\Domain;
    use Carbon\Carbon;
    
    $startDate = Carbon::now()->subDays($timeframe);
    
    // Get blacklist statistics
    $totalChecks = BlacklistResult::where('created_at', '>=', $startDate)->count();
    $listedResults = BlacklistResult::where('created_at', '>=', $startDate)->where('status', 'listed')->count();
    $cleanResults = $totalChecks - $listedResults;
    
    // Get unique domains checked
    $domainsChecked = BlacklistResult::where('created_at', '>=', $startDate)
        ->join('scans', 'blacklist_results.scan_id', '=', 'scans.id')
        ->distinct('scans.domain_id')
        ->count();
    
    // Get trending data (last 7 days vs previous 7 days)
    $recentChecks = BlacklistResult::where('created_at', '>=', Carbon::now()->subDays(7))->count();
    $previousChecks = BlacklistResult::whereBetween('created_at', [
        Carbon::now()->subDays(14),
        Carbon::now()->subDays(7)
    ])->count();
    
    $trend = $previousChecks > 0 ? (($recentChecks - $previousChecks) / $previousChecks) * 100 : 0;
    $trendDirection = $trend > 0 ? 'up' : ($trend < 0 ? 'down' : 'stable');
    
    // Get most active RBL providers
    $topProviders = BlacklistResult::where('created_at', '>=', $startDate)
        ->select('provider', \DB::raw('count(*) as checks'), \DB::raw('sum(case when status = "listed" then 1 else 0 end) as listings'))
        ->groupBy('provider')
        ->orderByDesc('checks')
        ->limit(5)
        ->get();
@endphp

<div class="bg-white rounded-lg shadow p-6">
    <div class="flex items-center justify-between mb-6">
        <h3 class="text-lg font-semibold text-gray-900">Blacklist Statistics</h3>
        <span class="text-sm text-gray-500">Last {{ $timeframe }} days</span>
    </div>

    <!-- Key Metrics -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="text-center p-4 bg-blue-50 rounded-lg">
            <div class="text-2xl font-bold text-blue-700">{{ number_format($totalChecks) }}</div>
            <div class="text-sm text-blue-600">Total Checks</div>
            @if($trend != 0)
                <div class="text-xs mt-1 flex items-center justify-center">
                    <i data-lucide="trending-{{ $trendDirection }}" class="w-3 h-3 mr-1 {{ $trendDirection === 'up' ? 'text-green-500' : 'text-red-500' }}"></i>
                    <span class="{{ $trendDirection === 'up' ? 'text-green-600' : 'text-red-600' }}">
                        {{ abs(round($trend, 1)) }}%
                    </span>
                </div>
            @endif
        </div>
        
        <div class="text-center p-4 bg-green-50 rounded-lg">
            <div class="text-2xl font-bold text-green-700">{{ number_format($cleanResults) }}</div>
            <div class="text-sm text-green-600">Clean Results</div>
            @if($totalChecks > 0)
                <div class="text-xs text-green-500 mt-1">
                    {{ round(($cleanResults / $totalChecks) * 100, 1) }}%
                </div>
            @endif
        </div>
        
        <div class="text-center p-4 bg-red-50 rounded-lg">
            <div class="text-2xl font-bold text-red-700">{{ number_format($listedResults) }}</div>
            <div class="text-sm text-red-600">Listed Results</div>
            @if($totalChecks > 0)
                <div class="text-xs text-red-500 mt-1">
                    {{ round(($listedResults / $totalChecks) * 100, 1) }}%
                </div>
            @endif
        </div>
        
        <div class="text-center p-4 bg-purple-50 rounded-lg">
            <div class="text-2xl font-bold text-purple-700">{{ number_format($domainsChecked) }}</div>
            <div class="text-sm text-purple-600">Domains Monitored</div>
        </div>
    </div>

    <!-- Top RBL Providers -->
    @if($topProviders->count() > 0)
        <div class="border-t pt-4">
            <h4 class="font-medium text-gray-900 mb-3">Top RBL Providers</h4>
            <div class="space-y-2">
                @foreach($topProviders as $provider)
                    <div class="flex items-center justify-between p-2 bg-gray-50 rounded">
                        <div class="flex items-center space-x-3">
                            <span class="font-medium text-sm">{{ $provider->provider }}</span>
                            <span class="text-xs text-gray-500">{{ number_format($provider->checks) }} checks</span>
                        </div>
                        <div class="flex items-center space-x-2">
                            @if($provider->listings > 0)
                                <span class="text-xs px-2 py-1 bg-red-100 text-red-700 rounded">
                                    {{ $provider->listings }} listed
                                </span>
                            @else
                                <span class="text-xs px-2 py-1 bg-green-100 text-green-700 rounded">
                                    All clean
                                </span>
                            @endif
                        </div>
                    </div>
                @endforeach
            </div>
        </div>
    @endif

    <!-- Quick Actions -->
    <div class="border-t pt-4 mt-4">
        <div class="flex items-center justify-between">
            <div class="text-sm text-gray-600">
                Last updated: {{ now()->format('M j, g:i A') }}
            </div>
            <div class="flex space-x-2">
                <a href="{{ route('schedules.index') }}" class="text-xs text-blue-600 hover:text-blue-800">
                    Manage Schedules
                </a>
                <span class="text-gray-300">•</span>
                <button onclick="refreshStats()" class="text-xs text-blue-600 hover:text-blue-800">
                    Refresh
                </button>
            </div>
        </div>
    </div>
</div>

<script>
function refreshStats() {
    // This would normally trigger an AJAX refresh
    window.location.reload();
}
</script>