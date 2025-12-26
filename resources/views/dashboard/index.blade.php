@extends('layouts.app')

@section('title', 'Dashboard')

@section('content')
<div class="space-y-6">
    <!-- Success Messages -->
    @if (session('status'))
        <div class="bg-emerald-50 border border-emerald-200 rounded-lg p-4">
            <div class="flex">
                <div class="flex-shrink-0">
                    <i data-lucide="check-circle" class="h-5 w-5 text-emerald-400"></i>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-emerald-800">
                        {{ session('status') }}
                    </p>
                </div>
            </div>
        </div>
    @endif

    <!-- Incident Alert Banner - FIRST (most important) -->
    @if(($incidentCount ?? 0) > 0)
    <div class="bg-gradient-to-r from-red-50 to-amber-50 border border-red-200 rounded-lg p-4">
        <div class="flex items-center justify-between">
            <div class="flex items-center">
                <div class="flex-shrink-0 p-2 bg-red-100 rounded-lg">
                    <i data-lucide="alert-triangle" class="h-5 w-5 text-red-600"></i>
                </div>
                <div class="ml-4">
                    <h3 class="text-sm font-semibold text-gray-900">{{ $incidentCount }} Active {{ Str::plural('Incident', $incidentCount) }}</h3>
                    <p class="text-sm text-gray-600">Security issues detected that need your attention</p>
                </div>
            </div>
            <a href="{{ route('monitoring.incidents') }}" 
               class="inline-flex items-center px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors">
                <i data-lucide="eye" class="w-4 h-4 mr-2"></i>
                View All
            </a>
        </div>
        @if($unresolvedIncidents->count() > 0)
        <div class="mt-3 pt-3 border-t border-red-200">
            <div class="flex flex-wrap gap-2">
                @foreach($unresolvedIncidents->take(3) as $incident)
                <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium 
                    {{ $incident->severity === 'incident' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800' }}">
                    <span class="w-1.5 h-1.5 rounded-full mr-1.5 {{ $incident->severity === 'incident' ? 'bg-red-500' : 'bg-amber-500' }}"></span>
                    {{ Str::limit($incident->message, 40) }}
                </span>
                @endforeach
                @if($unresolvedIncidents->count() > 3)
                <span class="text-xs text-gray-500 self-center">+{{ $unresolvedIncidents->count() - 3 }} more</span>
                @endif
            </div>
        </div>
        @endif
    </div>
    @endif

    <!-- Priority Actions Section -->
    @if($priorityActions->count() > 0)
    <div class="bg-white rounded-lg shadow-sm overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200 bg-gradient-to-r from-blue-50 to-indigo-50">
            <div class="flex items-center">
                <i data-lucide="zap" class="w-5 h-5 text-blue-600 mr-2"></i>
                <h2 class="text-lg font-semibold text-gray-900">What to Fix First</h2>
            </div>
            <p class="text-sm text-gray-600 mt-1">Priority actions to improve your email security</p>
        </div>
        <div class="divide-y divide-gray-100">
            @foreach($priorityActions as $action)
            <div class="p-4 hover:bg-gray-50 transition-colors">
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <div class="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center
                            {{ $action['severity'] === 'critical' ? 'bg-red-100' : 'bg-amber-100' }}">
                            <i data-lucide="{{ $action['icon'] }}" class="w-5 h-5 
                                {{ $action['severity'] === 'critical' ? 'text-red-600' : 'text-amber-600' }}"></i>
                        </div>
                        <div>
                            <div class="flex items-center gap-2">
                                <h3 class="text-sm font-semibold text-gray-900">{{ $action['title'] }}</h3>
                                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium
                                    {{ $action['severity'] === 'critical' ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700' }}">
                                    {{ ucfirst($action['severity']) }}
                                </span>
                            </div>
                            <p class="text-sm text-gray-600">{{ $action['description'] }}</p>
                        </div>
                    </div>
                    <a href="{{ $action['action_url'] }}" 
                       class="inline-flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors
                           {{ $action['severity'] === 'critical' ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-amber-600 hover:bg-amber-700 text-white' }}">
                        {{ $action['action_label'] }}
                        <i data-lucide="arrow-right" class="w-4 h-4 ml-1"></i>
                    </a>
                </div>
            </div>
            @endforeach
        </div>
    </div>
    @endif

    <!-- Risk-Based KPIs (action-driving metrics) -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <!-- Domains at Risk -->
        <div class="bg-white rounded-lg shadow-sm p-5 border-l-4 {{ ($domainsAtRisk ?? 0) > 0 ? 'border-red-500' : 'border-green-500' }}">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">Domains at Risk</p>
                    <p class="text-3xl font-bold {{ ($domainsAtRisk ?? 0) > 0 ? 'text-red-600' : 'text-green-600' }}">{{ $domainsAtRisk ?? 0 }}</p>
                    <p class="text-xs text-gray-500 mt-1">Score &lt;70 or blacklisted</p>
                </div>
                <div class="p-3 rounded-full {{ ($domainsAtRisk ?? 0) > 0 ? 'bg-red-100' : 'bg-green-100' }}">
                    <i data-lucide="{{ ($domainsAtRisk ?? 0) > 0 ? 'shield-alert' : 'shield-check' }}" class="w-6 h-6 {{ ($domainsAtRisk ?? 0) > 0 ? 'text-red-600' : 'text-green-600' }}"></i>
                </div>
            </div>
            @if(($domainsAtRisk ?? 0) > 0)
            <a href="{{ route('dashboard.domains') }}" class="mt-3 inline-flex items-center text-xs font-medium text-red-600 hover:text-red-700">
                View domains <i data-lucide="arrow-right" class="w-3 h-3 ml-1"></i>
            </a>
            @endif
        </div>

        <!-- Expiring Soon -->
        <div class="bg-white rounded-lg shadow-sm p-5 border-l-4 {{ ($expiringSoon ?? 0) > 0 ? 'border-amber-500' : 'border-green-500' }}">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">Expiring Soon</p>
                    <p class="text-3xl font-bold {{ ($expiringSoon ?? 0) > 0 ? 'text-amber-600' : 'text-green-600' }}">{{ $expiringSoon ?? 0 }}</p>
                    <p class="text-xs text-gray-500 mt-1">Domain or SSL &lt;30 days</p>
                </div>
                <div class="p-3 rounded-full {{ ($expiringSoon ?? 0) > 0 ? 'bg-amber-100' : 'bg-green-100' }}">
                    <i data-lucide="{{ ($expiringSoon ?? 0) > 0 ? 'calendar-x' : 'calendar-check' }}" class="w-6 h-6 {{ ($expiringSoon ?? 0) > 0 ? 'text-amber-600' : 'text-green-600' }}"></i>
                </div>
            </div>
            @if(($expiringSoon ?? 0) > 0)
            <a href="{{ route('dashboard.domains') }}" class="mt-3 inline-flex items-center text-xs font-medium text-amber-600 hover:text-amber-700">
                View domains <i data-lucide="arrow-right" class="w-3 h-3 ml-1"></i>
            </a>
            @endif
        </div>

        <!-- Needs Scanning -->
        <div class="bg-white rounded-lg shadow-sm p-5 border-l-4 {{ ($unscannedDomains ?? 0) > 0 ? 'border-blue-500' : 'border-green-500' }}">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">Needs Scanning</p>
                    <p class="text-3xl font-bold {{ ($unscannedDomains ?? 0) > 0 ? 'text-blue-600' : 'text-green-600' }}">{{ $unscannedDomains ?? 0 }}</p>
                    <p class="text-xs text-gray-500 mt-1">Not scanned in 7+ days</p>
                </div>
                <div class="p-3 rounded-full {{ ($unscannedDomains ?? 0) > 0 ? 'bg-blue-100' : 'bg-green-100' }}">
                    <i data-lucide="{{ ($unscannedDomains ?? 0) > 0 ? 'scan' : 'check-circle' }}" class="w-6 h-6 {{ ($unscannedDomains ?? 0) > 0 ? 'text-blue-600' : 'text-green-600' }}"></i>
                </div>
            </div>
            @if(($unscannedDomains ?? 0) > 0)
            <a href="{{ route('dashboard.domains') }}" class="mt-3 inline-flex items-center text-xs font-medium text-blue-600 hover:text-blue-700">
                Scan now <i data-lucide="arrow-right" class="w-3 h-3 ml-1"></i>
            </a>
            @endif
        </div>
    </div>

    <!-- Recent Activity (demoted - collapsible) -->
    <div class="bg-white rounded-lg shadow-sm" x-data="{ expanded: false }">
        <button @click="expanded = !expanded" class="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-gray-50 transition-colors">
            <div class="flex items-center gap-3">
                <i data-lucide="history" class="w-5 h-5 text-gray-400"></i>
                <span class="text-sm font-medium text-gray-700">Recent Scan Activity</span>
                <span class="text-xs text-gray-400">({{ $recentScans->count() ?? 0 }} recent)</span>
            </div>
            <div class="flex items-center gap-2">
                <a href="{{ route('dashboard.scans') }}" @click.stop class="text-blue-600 hover:text-blue-800 text-xs font-medium">
                    View All
                </a>
                <i data-lucide="chevron-down" class="w-4 h-4 text-gray-400 transition-transform" :class="{ 'rotate-180': expanded }"></i>
            </div>
        </button>
        
        <div x-show="expanded" x-collapse class="border-t border-gray-100">
            <div class="p-4">
                @if(isset($recentScans) && $recentScans->count() > 0)
                    <div class="space-y-2">
                        @foreach($recentScans->take(3) as $scan)
                            <a href="{{ route('scans.show', $scan->id) }}" class="flex items-center justify-between p-3 bg-gray-50 rounded-lg hover:bg-gray-100 transition-colors">
                                <div class="flex items-center space-x-3">
                                    <div class="flex-shrink-0">
                                        @if($scan->status === 'finished')
                                            <div class="w-6 h-6 bg-green-100 rounded-full flex items-center justify-center">
                                                <i data-lucide="check" class="w-3 h-3 text-green-600"></i>
                                            </div>
                                        @elseif($scan->status === 'failed')
                                            <div class="w-6 h-6 bg-red-100 rounded-full flex items-center justify-center">
                                                <i data-lucide="x" class="w-3 h-3 text-red-600"></i>
                                            </div>
                                        @else
                                            <div class="w-6 h-6 bg-gray-100 rounded-full flex items-center justify-center">
                                                <i data-lucide="clock" class="w-3 h-3 text-gray-600"></i>
                                            </div>
                                        @endif
                                    </div>
                                    <div>
                                        <p class="text-sm font-medium text-gray-900">{{ $scan->domain->domain }}</p>
                                        <p class="text-xs text-gray-500">{{ $scan->created_at->diffForHumans() }}</p>
                                    </div>
                                </div>
                                @if($scan->score !== null)
                                    <span class="text-sm font-bold 
                                        @if($scan->score >= 80) text-green-600
                                        @elseif($scan->score >= 60) text-yellow-600
                                        @else text-red-600
                                        @endif">
                                        {{ $scan->score }}%
                                    </span>
                                @endif
                            </a>
                        @endforeach
                    </div>
                @else
                    <p class="text-sm text-gray-500 text-center py-4">No scans yet</p>
                @endif
            </div>
        </div>
    </div>

    <!-- Quick Actions - Simplified single row -->
    <div class="flex flex-wrap gap-3">
        <a href="{{ route('dashboard.domains.create') }}" 
           class="inline-flex items-center px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors">
            <i data-lucide="plus" class="w-4 h-4 mr-2"></i>
            Add Domain
        </a>
        <a href="{{ route('dashboard.domains') }}" 
           class="inline-flex items-center px-4 py-2.5 bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 text-sm font-medium rounded-lg transition-colors">
            <i data-lucide="globe" class="w-4 h-4 mr-2"></i>
            Manage Domains
        </a>
        <a href="{{ route('schedules.index') }}" 
           class="inline-flex items-center px-4 py-2.5 bg-white border border-gray-300 hover:bg-gray-50 text-gray-700 text-sm font-medium rounded-lg transition-colors">
            <i data-lucide="calendar" class="w-4 h-4 mr-2"></i>
            Schedules
        </a>
    </div>
</div>
@endsection
