@props(['domains'])

@php
    $totalDomains = $domains->count();
    $domainsWithBlacklist = $domains->filter(function($domain) {
        return $domain->blacklist_status !== 'not-checked';
    })->count();
    $cleanDomains = $domains->filter(function($domain) {
        return $domain->blacklist_status === 'clean';
    })->count();
    $listedDomains = $domains->filter(function($domain) {
        return $domain->blacklist_status === 'listed';
    })->count();
    $scheduledBlacklistScans = $domains->filter(function($domain) {
        $schedule = $domain->activeSchedule;
        return $schedule && in_array($schedule->scan_type, ['blacklist', 'both']);
    })->count();
@endphp

<div class="bg-white rounded-lg shadow p-6">
    <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold text-gray-900">Blacklist Monitoring</h3>
        <a href="{{ route('schedules.index') }}" class="text-sm text-blue-600 hover:text-blue-800">
            Manage Schedules →
        </a>
    </div>

    <!-- Stats Grid -->
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div class="text-center p-3 bg-gray-50 rounded-lg">
            <div class="text-2xl font-bold text-gray-900">{{ $totalDomains }}</div>
            <div class="text-sm text-gray-600">Total Domains</div>
        </div>
        <div class="text-center p-3 bg-blue-50 rounded-lg">
            <div class="text-2xl font-bold text-blue-700">{{ $domainsWithBlacklist }}</div>
            <div class="text-sm text-blue-600">Monitored</div>
        </div>
        <div class="text-center p-3 bg-green-50 rounded-lg">
            <div class="text-2xl font-bold text-green-700">{{ $cleanDomains }}</div>
            <div class="text-sm text-green-600">Clean</div>
        </div>
        <div class="text-center p-3 bg-red-50 rounded-lg">
            <div class="text-2xl font-bold text-red-700">{{ $listedDomains }}</div>
            <div class="text-sm text-red-600">Listed</div>
        </div>
    </div>

    @if($listedDomains > 0)
        <!-- Alert for Listed Domains -->
        <div class="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <div class="flex items-start">
                <i data-lucide="alert-triangle" class="w-5 h-5 text-red-600 mt-0.5 mr-3 flex-shrink-0"></i>
                <div>
                    <h4 class="font-medium text-red-800">Action Required</h4>
                    <p class="text-sm text-red-700 mt-1">
                        {{ $listedDomains }} domain{{ $listedDomains > 1 ? 's are' : ' is' }} currently blacklisted. 
                        <a href="{{ route('dashboard.domains') }}" class="underline">Review and request delisting</a>.
                    </p>
                </div>
            </div>
        </div>
    @endif

    <!-- Recent Blacklist Activity -->
    @php
        $recentBlacklistScans = $domains->flatMap(function($domain) {
            return $domain->scans()->whereHas('blacklistResults')->latest()->take(3)->get();
        })->sortByDesc('created_at')->take(5);
    @endphp

    @if($recentBlacklistScans->count() > 0)
        <div class="border-t pt-4">
            <h4 class="font-medium text-gray-900 mb-3">Recent Blacklist Checks</h4>
            <div class="space-y-2">
                @foreach($recentBlacklistScans as $scan)
                    @php
                        $facts = json_decode($scan->facts_json, true) ?? [];
                        $summary = $facts['blacklist_summary'] ?? null;
                    @endphp
                    <div class="flex items-center justify-between p-2 bg-gray-50 rounded">
                        <div class="flex items-center space-x-3">
                            <span class="text-sm font-medium">{{ $scan->domain->domain }}</span>
                            @if($summary)
                                <x-blacklist-status-badge 
                                    :status="$summary['is_clean'] ? 'clean' : 'listed'" 
                                    :count="$summary['listed_count'] ?? 0" />
                            @endif
                        </div>
                        <div class="text-xs text-gray-500">
                            {{ $scan->created_at->diffForHumans() }}
                        </div>
                    </div>
                @endforeach
            </div>
        </div>
    @endif

    <!-- Scheduled Scans Info -->
    @if($scheduledBlacklistScans > 0)
        <div class="border-t pt-4 mt-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-2">
                    <i data-lucide="calendar" class="w-4 h-4 text-gray-500"></i>
                    <span class="text-sm text-gray-700">
                        {{ $scheduledBlacklistScans }} domain{{ $scheduledBlacklistScans > 1 ? 's have' : ' has' }} scheduled blacklist monitoring
                    </span>
                </div>
                <a href="{{ route('schedules.index') }}" class="text-xs text-blue-600 hover:text-blue-800">
                    View All
                </a>
            </div>
        </div>
    @endif
</div>