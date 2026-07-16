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

    @if(($totalDomains ?? 0) === 0)
    <!-- First-run onboarding -->
    <section class="overflow-hidden rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-700 shadow-sm">
        <div class="flex flex-col gap-8 p-6 text-white lg:flex-row lg:items-center lg:justify-between lg:p-8">
            <div class="max-w-2xl">
                <div class="inline-flex items-center rounded-full bg-white/15 px-3 py-1 text-xs font-medium text-blue-50 ring-1 ring-white/20">
                    <i data-lucide="sparkles" class="mr-1.5 h-3.5 w-3.5"></i>
                    First step
                </div>
                <h2 class="mt-4 text-3xl font-bold tracking-tight sm:text-4xl">Start by adding your first domain</h2>
                <p class="mt-3 text-base leading-7 text-blue-50 sm:text-lg">
                    MXScan will check your email security records, find missing protections, and show simple fixes.
                </p>
                <div class="mt-6 flex flex-col gap-3 sm:flex-row">
                    <a href="{{ route('dashboard.domains.create') }}"
                       class="inline-flex w-full items-center justify-center rounded-lg bg-white px-5 py-3 text-sm font-semibold text-blue-700 shadow-sm transition hover:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-white sm:w-auto">
                        <i data-lucide="plus" class="mr-2 h-4 w-4"></i>
                        Scan your first domain
                    </a>
                    <a href="{{ route('tools.index') }}"
                       class="inline-flex w-full items-center justify-center rounded-lg border border-white/30 px-5 py-3 text-sm font-semibold text-white transition hover:bg-white/10 sm:w-auto">
                        See what we check
                        <i data-lucide="arrow-right" class="ml-2 h-4 w-4"></i>
                    </a>
                </div>
            </div>
            <div class="rounded-2xl bg-white/10 p-5 ring-1 ring-white/20 lg:w-80">
                <div class="flex h-12 w-12 items-center justify-center rounded-xl bg-white text-blue-700">
                    <i data-lucide="shield-check" class="h-7 w-7"></i>
                </div>
                <p class="mt-4 text-sm leading-6 text-blue-50">
                    Add one domain and you will get a clear report for SPF, DKIM, DMARC, blacklist status, secure delivery records, and renewal risks.
                </p>
            </div>
        </div>
    </section>

    <section class="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div class="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
            <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-100 text-blue-700">
                <i data-lucide="globe" class="h-5 w-5"></i>
            </div>
            <h3 class="mt-4 text-sm font-semibold text-gray-900">1. Add domain</h3>
            <p class="mt-2 text-sm leading-6 text-gray-600">Enter your domain name, like example.com.</p>
        </div>
        <div class="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
            <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-indigo-100 text-indigo-700">
                <i data-lucide="scan" class="h-5 w-5"></i>
            </div>
            <h3 class="mt-4 text-sm font-semibold text-gray-900">2. Run first scan</h3>
            <p class="mt-2 text-sm leading-6 text-gray-600">We check SPF, DKIM, DMARC, blacklist status, and secure delivery records.</p>
        </div>
        <div class="rounded-xl border border-gray-200 bg-white p-5 shadow-sm">
            <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-100 text-emerald-700">
                <i data-lucide="wrench" class="h-5 w-5"></i>
            </div>
            <h3 class="mt-4 text-sm font-semibold text-gray-900">3. Fix what matters</h3>
            <p class="mt-2 text-sm leading-6 text-gray-600">You get clear explanations and copy-paste DNS records.</p>
        </div>
    </section>

    <section class="rounded-xl border border-blue-100 bg-blue-50 p-5">
        <div class="flex flex-col gap-3 sm:flex-row sm:items-start">
            <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-100 text-blue-700">
                <i data-lucide="lock-keyhole" class="h-5 w-5"></i>
            </div>
            <div>
                <h3 class="text-sm font-semibold text-gray-900">You stay in control</h3>
                <p class="mt-1 text-sm leading-6 text-gray-600">
                    MXScan only scans and explains what to fix. We never change your DNS automatically.
                </p>
            </div>
        </div>
    </section>
    @elseif($awaitingFirstScan ?? false)
    @php
        $pendingDomain = $firstScanDomain;
        $pendingScan = $firstScanPending;
    @endphp
    <section class="rounded-2xl border border-blue-200 bg-white p-6 shadow-sm">
        <div class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
                <p class="text-xs font-medium uppercase tracking-wide text-blue-600">Getting started</p>
                <h2 class="mt-1 text-xl font-semibold text-gray-900">{{ $pendingDomain?->domain ?? 'Your domain' }}</h2>
                @if($pendingScan && in_array($pendingScan->status, ['queued', 'running'], true))
                    <p class="mt-2 text-sm text-gray-600">First scan in progress</p>
                @elseif($pendingScan && $pendingScan->status === 'failed')
                    <p class="mt-2 text-sm text-red-600">The first scan failed. You can retry it.</p>
                @else
                    <p class="mt-2 text-sm text-gray-600">Your domain is ready to scan</p>
                @endif
            </div>
            <div class="flex flex-col gap-2 sm:flex-row">
                @if($pendingScan && in_array($pendingScan->status, ['queued', 'running'], true))
                    <a href="{{ route('reports.show', $pendingScan) }}"
                       class="mx-btn mx-btn-primary">
                        View scan progress
                    </a>
                @elseif($pendingScan && $pendingScan->status === 'failed')
                    <form method="POST" action="{{ route('domains.scan.now', $pendingDomain) }}">
                        @csrf
                        <input type="hidden" name="mode" value="full">
                        <button type="submit"
                                class="mx-btn mx-btn-primary mx-btn-block">
                            Retry scan
                        </button>
                    </form>
                @elseif($pendingDomain)
                    <form method="POST" action="{{ route('domains.scan.now', $pendingDomain) }}">
                        @csrf
                        <input type="hidden" name="mode" value="full">
                        <button type="submit"
                                class="mx-btn mx-btn-primary mx-btn-block">
                            Scan domain
                        </button>
                    </form>
                @endif
            </div>
        </div>
    </section>
    @else

    <header class="dashboard-page-heading">
        <div>
            <p class="dashboard-eyebrow">Overview</p>
            <h1>Dashboard</h1>
            <p>Your latest email-security posture and the actions that matter most.</p>
        </div>
    </header>

    @if(($finishedScanCount ?? 0) > 0 && $latestFinishedScan)
        <x-dashboard.dashboard-hero :hero="$dashboardHero" />
    @endif

    @if(($dashboardRecommendations ?? collect())->isNotEmpty())
    <section class="dashboard-priority-section" aria-labelledby="dashboard-priority-heading">
        <div class="dashboard-section-heading">
            <div>
                <h2 id="dashboard-priority-heading">What to fix first</h2>
                <p>Highest-impact action for your domain</p>
            </div>
        </div>
        <x-dashboard.dashboard-priority-action :recommendation="$dashboardRecommendations->first()" />

        @if($dashboardRecommendations->count() > 1)
        <div class="dashboard-next-actions">
            <h3>Next actions</h3>
            <div class="dashboard-recommendation-list">
                @foreach($dashboardRecommendations->skip(1) as $recommendation)
                    <x-dashboard.dashboard-recommendation-row :recommendation="$recommendation" />
                @endforeach
            </div>
        </div>
        @endif
    </section>
    @endif

    <section class="dashboard-metrics-section" aria-labelledby="dashboard-metrics-heading">
        <div class="dashboard-section-heading">
            <div>
                <h2 id="dashboard-metrics-heading">Domain health</h2>
                <p>Configuration, monitoring, and operational status at a glance.</p>
            </div>
        </div>
        <div class="dashboard-metric-grid">
            @foreach($dashboardMetrics as $metric)
                <x-dashboard.dashboard-metric-card :metric="$metric" />
            @endforeach
        </div>
    </section>

    <x-dashboard.dashboard-score-history
        :history="$dashboardScoreHistory"
        :latest-score="$dashboardHero['score'] ?? null"
        :latest-scan-id="$dashboardHero['scan_id'] ?? null"
    />

    @if(($incidentCount ?? 0) > 0)
    <section class="dashboard-incident-alert" aria-labelledby="dashboard-incidents-heading">
        <div>
            <p class="dashboard-eyebrow">Operational event</p>
            <h2 id="dashboard-incidents-heading">
                {{ $incidentCount }} active security {{ Str::plural('incident', $incidentCount) }}
            </h2>
            <p>Operational alerts and detected security events. Configuration findings are listed separately.</p>
        </div>
        <a href="{{ auth()->user()->canUseMonitoring() ? route('monitoring.incidents') : route('reports.index') }}"
           class="mx-btn mx-btn-danger">
            View incidents
        </a>
    </section>
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

    @endif
</div>
@endsection
