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
        <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div class="flex min-w-0 items-center">
                <div class="flex-shrink-0 p-2 bg-red-100 rounded-lg">
                    <i data-lucide="alert-triangle" class="h-5 w-5 text-red-600"></i>
                </div>
                <div class="ml-4">
                    <h3 class="text-sm font-semibold text-gray-900">{{ $incidentCount }} Active {{ Str::plural('Incident', $incidentCount) }}</h3>
                    <p class="text-sm text-gray-600">Security issues detected that need your attention</p>
                </div>
            </div>
            <a href="{{ auth()->user()->canUseMonitoring() ? route('monitoring.incidents') : route('reports.index') }}" 
               class="inline-flex w-full items-center justify-center px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm font-medium rounded-lg transition-colors sm:w-auto">
                <i data-lucide="eye" class="w-4 h-4 mr-2"></i>
                View All
            </a>
        </div>
        @if($unresolvedIncidents->count() > 0)
        <div class="mt-3 pt-3 border-t border-red-200 space-y-1">
            @foreach($unresolvedIncidents->take(3) as $incident)
            <a href="{{ $incident->action_url ?? route('monitoring.incidents') }}"
               class="flex min-w-0 items-center gap-2 px-3 py-2 rounded-lg hover:bg-white/60 transition-colors group">
                <span class="w-1.5 h-1.5 rounded-full shrink-0 {{ $incident->severity === 'incident' ? 'bg-red-500' : 'bg-amber-500' }}"></span>
                <span class="min-w-0 text-sm text-gray-800 truncate flex-1 group-hover:text-gray-900">{{ Str::limit($incident->message, 56) }}</span>
                <span class="hidden text-xs text-gray-500 shrink-0 sm:inline">{{ $incident->domain->domain ?? '' }}</span>
                <i data-lucide="chevron-right" class="w-4 h-4 text-gray-400 shrink-0"></i>
            </a>
            @endforeach
            @if($unresolvedIncidents->count() > 3)
            <p class="text-xs text-gray-500 px-3 pt-1">+{{ $unresolvedIncidents->count() - 3 }} more in incident list</p>
            @endif
            @if(auth()->user()->canUseMonitoring())
            <a href="{{ route('settings.notifications') }}" class="inline-flex items-center text-xs text-blue-700 hover:text-blue-800 px-3 pt-2">
                <i data-lucide="bell" class="w-3 h-3 mr-1"></i>
                Configure Slack &amp; webhooks
            </a>
            @endif
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
                <div class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div class="flex min-w-0 items-center space-x-4">
                        <div class="flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center
                            {{ $action['severity'] === 'critical' ? 'bg-red-100' : 'bg-amber-100' }}">
                            <i data-lucide="{{ $action['icon'] }}" class="w-5 h-5 
                                {{ $action['severity'] === 'critical' ? 'text-red-600' : 'text-amber-600' }}"></i>
                        </div>
                        <div class="min-w-0">
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
                       class="inline-flex w-full items-center justify-center px-3 py-2 text-sm font-medium rounded-lg transition-colors sm:w-auto
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

        <!-- Monitoring gap -->
        <div class="bg-white rounded-lg shadow-sm p-5 border-l-4 {{ ($monitoringGap ?? 0) > 0 ? 'border-blue-500' : 'border-green-500' }}">
            <div class="flex items-center justify-between">
                <div>
                    <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">Monitoring Gap</p>
                    <p class="text-3xl font-bold {{ ($monitoringGap ?? 0) > 0 ? 'text-blue-600' : 'text-green-600' }}">{{ $monitoringGap ?? 0 }}</p>
                    <p class="text-xs text-gray-500 mt-1">
                        @if(($monitoringGap ?? 0) > 0)
                            Automated scan overdue
                        @else
                            All domains monitored on schedule
                        @endif
                    </p>
                </div>
                <div class="p-3 rounded-full {{ ($monitoringGap ?? 0) > 0 ? 'bg-blue-100' : 'bg-green-100' }}">
                    <i data-lucide="{{ ($monitoringGap ?? 0) > 0 ? 'clock' : 'check-circle' }}" class="w-6 h-6 {{ ($monitoringGap ?? 0) > 0 ? 'text-blue-600' : 'text-green-600' }}"></i>
                </div>
            </div>
            @if(($monitoringGap ?? 0) > 0)
            <a href="{{ route('domains') }}" class="mt-3 inline-flex items-center text-xs font-medium text-blue-600 hover:text-blue-700">
                Review domains <i data-lucide="arrow-right" class="w-3 h-3 ml-1"></i>
            </a>
            @endif
        </div>
    </div>

    <!-- DMARC + monitoring summary -->
    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <a href="{{ route('dmarc.index') }}" class="bg-white rounded-lg shadow-sm p-4 border border-gray-200 hover:border-blue-300 transition-colors">
            <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">DMARC volume (7d)</p>
            <p class="text-2xl font-bold text-gray-900 mt-1">
                @if($dmarcDashboard['has_data'] ?? false)
                    {{ number_format($dmarcDashboard['total_volume']) }}
                @else
                    —
                @endif
            </p>
            <p class="text-xs text-gray-500 mt-1">
                @if($dmarcDashboard['has_data'] ?? false)
                    {{ $dmarcDashboard['alignment_rate'] }}% aligned
                @else
                    Set up DMARC reporting
                @endif
            </p>
        </a>
        <a href="{{ route('monitoring.incidents') }}" class="bg-white rounded-lg shadow-sm p-4 border border-gray-200 hover:border-red-300 transition-colors">
            <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">Active incidents</p>
            <p class="text-2xl font-bold {{ ($incidentCount ?? 0) > 0 ? 'text-red-600' : 'text-green-600' }} mt-1">{{ $incidentCount ?? 0 }}</p>
            <p class="text-xs text-gray-500 mt-1">Unresolved security issues</p>
        </a>
        <a href="{{ route('automations.index') }}" class="bg-white rounded-lg shadow-sm p-4 border border-gray-200 hover:border-blue-300 transition-colors">
            <p class="text-xs font-medium text-gray-500 uppercase tracking-wide">Automations</p>
            <p class="text-2xl font-bold text-gray-900 mt-1">{{ $domains->where(fn($d) => $d->activeSchedule)->count() }}</p>
            <p class="text-xs text-gray-500 mt-1">Domains with scheduled scans</p>
        </a>
    </div>

    @if(!empty($scoreTrend['labels']))
    @include('dashboard.partials._score-trend', ['scoreTrend' => $scoreTrend, 'chartId' => 'dashboardScoreTrend'])
    @endif

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

</div>
@endsection
