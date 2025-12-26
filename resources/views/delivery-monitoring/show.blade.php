@extends('layouts.app')

@section('page-title', $monitor->label)

@section('content')
<div class="space-y-6" x-data="deliveryMonitor()">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
            <div class="flex items-center space-x-3">
                <a href="{{ route('delivery-monitoring.index') }}" class="text-gray-400 hover:text-gray-600">
                    <i data-lucide="arrow-left" class="w-5 h-5"></i>
                </a>
                <h1 class="text-2xl font-bold text-gray-900">{{ $monitor->label }}</h1>
                @if($monitor->status === 'active')
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                        Active
                    </span>
                @else
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                        Paused
                    </span>
                @endif
            </div>
            @if($monitor->domain)
                <p class="text-gray-600 mt-1">Monitoring for: {{ $monitor->domain->domain }}</p>
            @endif
        </div>
        <div class="flex items-center space-x-2">
            @if($monitor->status === 'active')
                <form method="POST" action="{{ route('delivery-monitoring.pause', $monitor) }}" class="inline">
                    @csrf
                    <button type="submit" class="px-4 py-2 bg-yellow-100 hover:bg-yellow-200 text-yellow-800 rounded-lg flex items-center space-x-2">
                        <i data-lucide="pause-circle" class="w-4 h-4"></i>
                        <span class="hidden sm:inline">Pause</span>
                    </button>
                </form>
            @else
                <form method="POST" action="{{ route('delivery-monitoring.resume', $monitor) }}" class="inline">
                    @csrf
                    <button type="submit" class="px-4 py-2 bg-green-100 hover:bg-green-200 text-green-800 rounded-lg flex items-center space-x-2">
                        <i data-lucide="play-circle" class="w-4 h-4"></i>
                        <span class="hidden sm:inline">Resume</span>
                    </button>
                </form>
            @endif
            <form method="POST" action="{{ route('delivery-monitoring.destroy', $monitor) }}" 
                  class="inline" 
                  onsubmit="return confirm('Are you sure you want to delete this monitor? All check history will be lost.');">
                @csrf
                @method('DELETE')
                <button type="submit" class="px-4 py-2 bg-red-100 hover:bg-red-200 text-red-800 rounded-lg flex items-center space-x-2">
                    <i data-lucide="trash-2" class="w-4 h-4"></i>
                    <span class="hidden sm:inline">Delete</span>
                </button>
            </form>
        </div>
    </div>

    @php
    // Calculate last message age and color
    $lastCheckAge = null;
    $lastCheckColor = 'gray';
    if ($monitor->last_check_at) {
        $minutesAgo = $monitor->last_check_at->diffInMinutes(now());
        $lastCheckAge = $monitor->last_check_at->diffForHumans();
        if ($minutesAgo < 10) {
            $lastCheckColor = 'green';
        } elseif ($minutesAgo < 60) {
            $lastCheckColor = 'amber';
        } else {
            $lastCheckColor = 'red';
        }
    }
    
    // Check if stale
    $isStale = !$monitor->last_check_at || $monitor->last_check_at->lt(now()->subMinutes(60));
    @endphp

    <!-- Stale Warning Banner -->
    @if($isStale)
        <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
            <div class="flex">
                <div class="flex-shrink-0">
                    <i data-lucide="alert-triangle" class="h-5 w-5 text-yellow-400"></i>
                </div>
                <div class="ml-3">
                    <p class="text-sm text-yellow-700">
                        <strong class="font-medium">We haven't seen a test recently.</strong>
                        Send one now to verify your email delivery is working correctly.
                    </p>
                </div>
            </div>
        </div>
    @endif

    <!-- What This Test Proves - Educational Banner -->
    <div class="bg-white border border-gray-200 rounded-lg p-4 mb-4">
        <div class="flex items-start gap-3">
            <div class="p-2 bg-blue-100 rounded-lg flex-shrink-0">
                <i data-lucide="info" class="w-5 h-5 text-blue-600"></i>
            </div>
            <div>
                <h3 class="text-sm font-semibold text-gray-900 mb-1">What this test proves</h3>
                <p class="text-sm text-gray-600">When you send a test email here, we verify that your mail server is correctly configured:</p>
                <ul class="mt-2 text-sm text-gray-600 space-y-1">
                    <li class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span><strong>SPF</strong> — Your server is authorized to send for your domain</li>
                    <li class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span><strong>DKIM</strong> — Email signature is valid and wasn't tampered with</li>
                    <li class="flex items-center gap-2"><span class="w-1.5 h-1.5 rounded-full bg-blue-500"></span><strong>DMARC</strong> — Your domain policy is being applied correctly</li>
                </ul>
            </div>
        </div>
    </div>

    <!-- Send a Test Card -->
    <div class="bg-gradient-to-br from-blue-50 to-indigo-50 border border-blue-200 rounded-lg p-6">
        <div class="flex items-start justify-between mb-4">
            <div>
                <h2 class="text-lg font-semibold text-gray-900 mb-1">Send a Test Email</h2>
                <p class="text-sm text-gray-600">Send from your actual mail server (not Gmail/Outlook personal) to test authentication</p>
            </div>
            <div class="relative" x-data="{ open: false }">
                <button @click="open = !open" 
                        class="text-blue-600 hover:text-blue-800 p-1 rounded-full hover:bg-blue-100"
                        aria-label="Help">
                    <i data-lucide="help-circle" class="w-5 h-5"></i>
                </button>
                <div x-show="open" 
                     @click.away="open = false"
                     x-transition
                     class="absolute right-0 mt-2 w-72 bg-white rounded-lg shadow-lg border border-gray-200 p-4 z-10">
                    <h4 class="font-semibold text-gray-900 mb-2">How to send from Gmail/Outlook:</h4>
                    <ol class="list-decimal list-inside space-y-1 text-sm text-gray-700">
                        <li>Click "Open email app" below or copy the address</li>
                        <li>Send from your actual mail server (not personal email)</li>
                        <li>Results appear within 5 minutes</li>
                    </ol>
                </div>
            </div>
        </div>
        
        <div class="bg-white rounded-lg p-4 mb-4">
            <div class="flex items-center justify-between mb-2">
                <label class="text-xs font-medium text-gray-500 uppercase">Test Address</label>
            </div>
            <code class="text-sm font-mono bg-gray-50 px-3 py-2 rounded block break-all border border-gray-200">{{ $monitor->inbox_address }}</code>
        </div>
        
        <div class="flex flex-wrap gap-2">
            <button @click="copyAddress('{{ $monitor->inbox_address }}')" 
                    class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center space-x-2 transition">
                <i data-lucide="copy" class="w-4 h-4"></i>
                <span>Copy Address</span>
            </button>
            <a href="mailto:{{ $monitor->inbox_address }}?subject=Deliverability test {{ $monitor->token }}" 
               class="px-4 py-2 bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 rounded-lg flex items-center space-x-2 transition">
                <i data-lucide="mail" class="w-4 h-4"></i>
                <span>Open Email App</span>
            </a>
        </div>
    </div>

    <!-- Status Tiles -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <!-- Last Message Age -->
        <div class="bg-white rounded-lg shadow-sm p-6 border-l-4 border-{{ $lastCheckColor }}-500">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-medium text-gray-500">Last Message</h3>
                <div class="w-2 h-2 rounded-full bg-{{ $lastCheckColor }}-500"></div>
            </div>
            @if($lastCheckAge)
                <p class="text-2xl font-bold text-gray-900">{{ $lastCheckAge }}</p>
                <p class="text-xs text-gray-500 mt-1">{{ $monitor->last_check_at->format('M d, Y H:i') }}</p>
            @else
                <p class="text-2xl font-bold text-gray-400">No messages yet</p>
                <p class="text-xs text-gray-500 mt-1">Send a test to get started</p>
            @endif
        </div>

        <!-- TTI Insights (24h) -->
        <div class="bg-white rounded-lg shadow-sm p-6">
            <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-medium text-gray-500">TTI (24h)</h3>
                @if($stats['tti_sample_size'] ?? 0 > 0)
                    <span class="text-xs text-gray-400 cursor-help" title="Time-to-Inbox: Time between sending and receiving email. High P95 indicates sporadic queueing.">
                        n={{ $stats['tti_sample_size'] }}
                    </span>
                @endif
            </div>
            @if($stats['median_tti_24h'])
                <div class="space-y-2">
                    <div class="flex items-baseline justify-between">
                        <span class="text-xs text-gray-600">Median</span>
                        @php
                        $medianSeconds = $stats['median_tti_24h'];
                        $medianFormatted = $medianSeconds < 60 
                            ? $medianSeconds . 's'
                            : floor($medianSeconds / 60) . 'm ' . ($medianSeconds % 60) . 's';
                        @endphp
                        <span class="text-2xl font-bold text-gray-900">{{ $medianFormatted }}</span>
                    </div>
                    @if($stats['p95_tti_24h'])
                        <div class="flex items-baseline justify-between">
                            <span class="text-xs text-gray-600">P95</span>
                            @php
                            $p95Seconds = $stats['p95_tti_24h'];
                            $p95Formatted = $p95Seconds < 60 
                                ? $p95Seconds . 's'
                                : floor($p95Seconds / 60) . 'm ' . ($p95Seconds % 60) . 's';
                            $p95Color = $p95Seconds > 1800 ? 'text-red-600' : ($p95Seconds > 300 ? 'text-amber-600' : 'text-green-600');
                            @endphp
                            <span class="text-lg font-semibold {{ $p95Color }}">
                                {{ $p95Formatted }}
                            </span>
                        </div>
                    @endif
                </div>
            @else
                <p class="text-2xl font-bold text-gray-400">—</p>
                <p class="text-xs text-gray-500 mt-1">No data yet</p>
            @endif
        </div>

        <!-- Auth Pass Rates (24h) -->
        <div class="bg-white rounded-lg shadow-sm p-6">
            <h3 class="text-sm font-medium text-gray-500 mb-2">Test Results (24h)</h3>
            <div class="space-y-2">
                <div class="flex items-center justify-between">
                    <span class="text-xs text-gray-600">SPF</span>
                    <div class="flex items-center space-x-1">
                        <span class="text-sm font-semibold {{ $stats['spf_pass_rate'] >= 90 ? 'text-green-600' : ($stats['spf_pass_rate'] >= 70 ? 'text-amber-600' : 'text-red-600') }}">
                            {{ $stats['spf_pass_rate'] ?? '—' }}{{ $stats['spf_pass_rate'] ? '%' : '' }}
                        </span>
                        @if($stats['spf_sample_size'] ?? 0 > 0)
                            <span class="text-xs text-gray-500">({{ $stats['spf_sample_size'] }})</span>
                        @endif
                        @if(($stats['spf_none_count'] ?? 0) > 0)
                            <span class="text-xs text-gray-400 cursor-help" title="{{ $stats['spf_none_count'] }} checks with no SPF result (none/undecidable)">
                                +{{ $stats['spf_none_count'] }} none
                            </span>
                        @endif
                    </div>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-xs text-gray-600">DKIM</span>
                    <div class="flex items-center space-x-1">
                        <span class="text-sm font-semibold {{ $stats['dkim_pass_rate'] >= 90 ? 'text-green-600' : ($stats['dkim_pass_rate'] >= 70 ? 'text-amber-600' : 'text-red-600') }}">
                            {{ $stats['dkim_pass_rate'] ?? '—' }}{{ $stats['dkim_pass_rate'] ? '%' : '' }}
                        </span>
                        @if($stats['dkim_sample_size'] ?? 0 > 0)
                            <span class="text-xs text-gray-500">({{ $stats['dkim_sample_size'] }})</span>
                        @endif
                        @if(($stats['dkim_none_count'] ?? 0) > 0)
                            <span class="text-xs text-gray-400 cursor-help" title="{{ $stats['dkim_none_count'] }} checks with no DKIM signature">
                                +{{ $stats['dkim_none_count'] }} none
                            </span>
                        @endif
                    </div>
                </div>
                <div class="flex items-center justify-between">
                    <span class="text-xs text-gray-600">DMARC</span>
                    <div class="flex items-center space-x-1">
                        <span class="text-sm font-semibold {{ $stats['dmarc_pass_rate'] >= 90 ? 'text-green-600' : ($stats['dmarc_pass_rate'] >= 70 ? 'text-amber-600' : 'text-red-600') }}">
                            {{ $stats['dmarc_pass_rate'] ?? '—' }}{{ $stats['dmarc_pass_rate'] ? '%' : '' }}
                        </span>
                        @if($stats['dmarc_sample_size'] ?? 0 > 0)
                            <span class="text-xs text-gray-500">({{ $stats['dmarc_sample_size'] }})</span>
                        @endif
                        @if(($stats['dmarc_none_count'] ?? 0) > 0)
                            <span class="text-xs text-gray-400 cursor-help" title="{{ $stats['dmarc_none_count'] }} checks with no DMARC result">
                                +{{ $stats['dmarc_none_count'] }} none
                            </span>
                        @endif
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Test Failure vs Real Risk Explainer -->
    @php
        $hasFailures = ($stats['spf_pass_rate'] ?? 100) < 100 || ($stats['dkim_pass_rate'] ?? 100) < 100 || ($stats['dmarc_pass_rate'] ?? 100) < 100;
    @endphp
    @if($hasFailures)
    <div class="bg-amber-50 border border-amber-200 rounded-lg p-4">
        <div class="flex items-start gap-3">
            <div class="p-2 bg-amber-100 rounded-lg flex-shrink-0">
                <i data-lucide="help-circle" class="w-5 h-5 text-amber-600"></i>
            </div>
            <div>
                <h3 class="text-sm font-semibold text-amber-900 mb-1">Test failure ≠ Deliverability problem</h3>
                <p class="text-sm text-amber-800 mb-2">A failed test doesn't always mean your emails won't be delivered. Common causes:</p>
                <ul class="text-sm text-amber-700 space-y-1">
                    <li class="flex items-start gap-2">
                        <span class="text-amber-500 mt-0.5">•</span>
                        <span><strong>Sent from wrong server</strong> — Personal Gmail/Outlook won't pass SPF for your domain</span>
                    </li>
                    <li class="flex items-start gap-2">
                        <span class="text-amber-500 mt-0.5">•</span>
                        <span><strong>DKIM not configured</strong> — Your mail server may not sign emails (common with shared hosting)</span>
                    </li>
                    <li class="flex items-start gap-2">
                        <span class="text-amber-500 mt-0.5">•</span>
                        <span><strong>DMARC policy = none</strong> — Failures are reported but emails still delivered</span>
                    </li>
                </ul>
                <p class="text-sm text-amber-800 mt-2"><strong>Action needed?</strong> Only if you see consistent failures from your production mail server.</p>
            </div>
        </div>
    </div>
    @endif

    <!-- Collapsible Legend -->
    <div class="bg-white rounded-lg shadow-sm overflow-hidden" x-data="{ open: false }">
        <button @click="open = !open" 
                class="w-full px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition"
                :aria-expanded="open">
            <div class="flex items-center space-x-2">
                <i data-lucide="info" class="w-5 h-5 text-blue-600"></i>
                <h3 class="text-sm font-semibold text-gray-900">What do these mean?</h3>
            </div>
            <i data-lucide="chevron-down" class="w-5 h-5 text-gray-400 transition-transform" :class="{ 'rotate-180': open }"></i>
        </button>
        
        <div x-show="open" 
             x-collapse
             class="px-6 pb-6 border-t border-gray-200">
            <div class="grid md:grid-cols-2 gap-6 pt-4">
                <!-- Authentication Protocols -->
                <div>
                    <h4 class="font-semibold text-gray-900 mb-3">Authentication Protocols</h4>
                    <dl class="space-y-3 text-sm">
                        <div>
                            <dt class="font-medium text-gray-700 mb-1">SPF (Sender Policy Framework)</dt>
                            <dd class="text-gray-600">Verifies the sending mail server is authorized to send for your domain.</dd>
                            <div class="flex gap-2 mt-1">
                                <x-delivery.auth-chip :value="true" label="Pass" />
                                <x-delivery.auth-chip :value="false" label="Fail" />
                                <x-delivery.auth-chip :value="null" label="None" />
                            </div>
                        </div>
                        <div>
                            <dt class="font-medium text-gray-700 mb-1">DKIM (DomainKeys Identified Mail)</dt>
                            <dd class="text-gray-600">Cryptographic signature proves the email wasn't tampered with in transit.</dd>
                        </div>
                        <div>
                            <dt class="font-medium text-gray-700 mb-1">DMARC (Domain-based Message Authentication)</dt>
                            <dd class="text-gray-600">Policy that tells receivers what to do if SPF or DKIM fails.</dd>
                        </div>
                    </dl>
                </div>
                
                <!-- TTI & Verdict -->
                <div>
                    <h4 class="font-semibold text-gray-900 mb-3">Metrics & Verdicts</h4>
                    <dl class="space-y-3 text-sm">
                        <div>
                            <dt class="font-medium text-gray-700 mb-1">Time-to-Inbox (TTI)</dt>
                            <dd class="text-gray-600 mb-1">Time between sending and receiving the email.</dd>
                            <div class="space-y-1">
                                <div class="flex items-center"><span class="w-2 h-2 rounded-full bg-green-500 mr-2"></span><span class="text-gray-700">&lt; 5 minutes: Excellent</span></div>
                                <div class="flex items-center"><span class="w-2 h-2 rounded-full bg-amber-500 mr-2"></span><span class="text-gray-700">5–30 minutes: Good</span></div>
                                <div class="flex items-center"><span class="w-2 h-2 rounded-full bg-red-500 mr-2"></span><span class="text-gray-700">&gt; 30 minutes: Slow</span></div>
                            </div>
                        </div>
                        <div>
                            <dt class="font-medium text-gray-700 mb-1">Verdict</dt>
                            <dd class="text-gray-600 mb-1">Overall assessment of the delivery check.</dd>
                            <div class="flex gap-2">
                                <x-delivery.verdict-badge verdict="ok" />
                                <x-delivery.verdict-badge verdict="warning" />
                                <x-delivery.verdict-badge verdict="incident" />
                            </div>
                        </div>
                    </dl>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Checks -->
    @if($checks->count() > 0)
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <!-- Header with Filters -->
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <h2 class="text-lg font-semibold text-gray-900">Recent Checks ({{ $checks->total() }})</h2>
                    
                    <!-- Filters -->
                    <div class="flex flex-wrap gap-2">
                        <div class="flex items-center space-x-2">
                            <label class="text-sm text-gray-600">Timeframe:</label>
                            <select onchange="window.location.href='?range=' + this.value + '&verdict={{ $verdict }}'" 
                                    class="text-sm border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                                <option value="24h" {{ $range === '24h' ? 'selected' : '' }}>24 hours</option>
                                <option value="7d" {{ $range === '7d' ? 'selected' : '' }}>7 days</option>
                                <option value="30d" {{ $range === '30d' ? 'selected' : '' }}>30 days</option>
                            </select>
                        </div>
                        
                        <div class="flex items-center space-x-2">
                            <label class="text-sm text-gray-600">Verdict:</label>
                            <select onchange="window.location.href='?range={{ $range }}&verdict=' + this.value" 
                                    class="text-sm border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                                <option value="all" {{ $verdict === 'all' ? 'selected' : '' }}>All</option>
                                <option value="ok" {{ $verdict === 'ok' ? 'selected' : '' }}>OK</option>
                                <option value="warning" {{ $verdict === 'warning' ? 'selected' : '' }}>Warning</option>
                                <option value="incident" {{ $verdict === 'incident' ? 'selected' : '' }}>Incident</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="overflow-x-auto">
                <table class="w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Received</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden md:table-cell">From</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden lg:table-cell">Subject</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">SPF</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">DKIM</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">DMARC</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden xl:table-cell">TTI</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Verdict</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        @foreach($checks as $check)
                            <tr class="hover:bg-gray-50">
                                <td class="px-3 py-4 whitespace-nowrap">
                                    <div class="text-sm text-gray-900" title="{{ $check->received_at->format('Y-m-d H:i:s') }}">
                                        {{ $check->received_at->format('M d, H:i') }}
                                    </div>
                                    <div class="text-xs text-gray-500">{{ $check->received_at->diffForHumans() }}</div>
                                </td>
                                <td class="px-3 py-4 hidden md:table-cell">
                                    <div class="text-sm text-gray-900 truncate max-w-xs">{{ $check->from_addr ?? '—' }}</div>
                                </td>
                                <td class="px-3 py-4 hidden lg:table-cell">
                                    <div class="text-sm text-gray-900 truncate max-w-xs">{{ $check->subject ?? '—' }}</div>
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap">
                                    <x-delivery.auth-chip :value="$check->spf_pass" label="SPF" />
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap">
                                    <x-delivery.auth-chip :value="$check->dkim_pass" label="DKIM" />
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap">
                                    <x-delivery.auth-chip :value="$check->dmarc_pass" label="DMARC" />
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap hidden xl:table-cell">
                                    @if($check->tti_ms)
                                        @php
                                        $ttiSeconds = $check->getTtiSeconds();
                                        $ttiColor = $ttiSeconds < 300 ? 'text-green-600' : ($ttiSeconds < 1800 ? 'text-amber-600' : 'text-red-600');
                                        @endphp
                                        <span class="text-sm font-medium {{ $ttiColor }}">
                                            {{ $check->getFormattedTti() }}
                                        </span>
                                    @else
                                        <span class="text-xs text-gray-400">—</span>
                                    @endif
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap">
                                    <x-delivery.verdict-badge :verdict="$check->verdict" />
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap">
                                    <button @click="showDetails({{ $check->id }})" 
                                            class="text-blue-600 hover:text-blue-800 text-sm font-medium">
                                        Details
                                    </button>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            @if($checks->hasPages())
                <div class="px-6 py-4 border-t border-gray-200">
                    {{ $checks->links() }}
                </div>
            @endif
        </div>
    @else
        <!-- Empty State -->
        <div class="bg-white rounded-lg shadow-sm p-12 text-center">
            <div class="mx-auto h-24 w-24 text-gray-400 mb-4">
                <svg class="w-full h-full" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                </svg>
            </div>
            <h3 class="text-lg font-medium text-gray-900 mb-2">No checks yet</h3>
            <p class="text-gray-600 mb-6 max-w-md mx-auto">
                Send a test email to get started with delivery monitoring.
            </p>
            
            <!-- Repeat instructions in empty state -->
            <div class="bg-gray-50 rounded-lg p-6 max-w-lg mx-auto text-left">
                <h4 class="font-semibold text-gray-900 mb-3">Quick Start:</h4>
                <ol class="list-decimal list-inside space-y-2 text-sm text-gray-700">
                    <li>Copy the test address above</li>
                    <li>Send an email from your mail server to that address</li>
                    <li>Results will appear here within 5 minutes</li>
                </ol>
                <div class="mt-4 p-3 bg-white rounded border border-gray-200">
                    <code class="text-xs break-all">{{ $monitor->inbox_address }}</code>
                </div>
            </div>
        </div>
    @endif

    <!-- Details Slide-over -->
    <div x-show="detailsOpen" 
         x-cloak
         @keydown.escape.window="detailsOpen = false"
         class="fixed inset-0 overflow-hidden z-50" 
         aria-labelledby="slide-over-title" 
         role="dialog" 
         aria-modal="true">
        <div class="absolute inset-0 overflow-hidden">
            <!-- Background overlay -->
            <div x-show="detailsOpen"
                 x-transition:enter="ease-in-out duration-300"
                 x-transition:enter-start="opacity-0"
                 x-transition:enter-end="opacity-100"
                 x-transition:leave="ease-in-out duration-300"
                 x-transition:leave-start="opacity-100"
                 x-transition:leave-end="opacity-0"
                 @click="detailsOpen = false"
                 class="absolute inset-0 bg-gray-500 bg-opacity-75 transition-opacity" 
                 aria-hidden="true"></div>

            <div class="fixed inset-y-0 right-0 pl-10 max-w-full flex">
                <div x-show="detailsOpen"
                     x-transition:enter="transform transition ease-in-out duration-300"
                     x-transition:enter-start="translate-x-full"
                     x-transition:enter-end="translate-x-0"
                     x-transition:leave="transform transition ease-in-out duration-300"
                     x-transition:leave-start="translate-x-0"
                     x-transition:leave-end="translate-x-full"
                     class="w-screen max-w-2xl">
                    <div class="h-full flex flex-col bg-white shadow-xl overflow-y-scroll">
                        <!-- Header -->
                        <div class="px-6 py-6 bg-gray-50 border-b border-gray-200">
                            <div class="flex items-start justify-between">
                                <h2 class="text-lg font-semibold text-gray-900" id="slide-over-title">
                                    Check Details
                                </h2>
                                <button @click="detailsOpen = false" 
                                        class="text-gray-400 hover:text-gray-500">
                                    <i data-lucide="x" class="w-6 h-6"></i>
                                </button>
                            </div>
                        </div>

                        <!-- Content -->
                        <div class="flex-1 px-6 py-6" x-show="selectedCheck">
                            <div class="space-y-6">
                                <!-- Basic Info -->
                                <div>
                                    <h3 class="text-sm font-semibold text-gray-900 mb-3">Message Information</h3>
                                    <dl class="space-y-2 text-sm">
                                        <div class="flex justify-between">
                                            <dt class="text-gray-600">Received:</dt>
                                            <dd class="text-gray-900 font-medium" x-text="selectedCheck?.received_at"></dd>
                                        </div>
                                        <div class="flex justify-between">
                                            <dt class="text-gray-600">From:</dt>
                                            <dd class="text-gray-900 font-medium truncate ml-4" x-text="selectedCheck?.from_addr || '—'"></dd>
                                        </div>
                                        <div class="flex justify-between">
                                            <dt class="text-gray-600">Subject:</dt>
                                            <dd class="text-gray-900 font-medium truncate ml-4" x-text="selectedCheck?.subject || '—'"></dd>
                                        </div>
                                        <div class="flex justify-between">
                                            <dt class="text-gray-600">TTI:</dt>
                                            <dd class="text-gray-900 font-medium" x-text="selectedCheck?.tti || '—'"></dd>
                                        </div>
                                    </dl>
                                </div>

                                <!-- Authentication Results -->
                                <div>
                                    <div class="flex items-center justify-between mb-3">
                                        <h3 class="text-sm font-semibold text-gray-900">Authentication Results</h3>
                                        <span x-show="selectedCheck?.verified_by_app" 
                                              class="inline-flex items-center px-2 py-1 rounded-md text-xs font-medium bg-blue-100 text-blue-800 border border-blue-200">
                                            <svg class="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                            </svg>
                                            Verified by MXScan
                                        </span>
                                    </div>
                                    <div class="space-y-3">
                                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                            <span class="text-sm text-gray-700">SPF</span>
                                            <span x-html="selectedCheck?.spf_badge"></span>
                                        </div>
                                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                            <span class="text-sm text-gray-700">DKIM</span>
                                            <span x-html="selectedCheck?.dkim_badge"></span>
                                        </div>
                                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                            <span class="text-sm text-gray-700">DMARC</span>
                                            <span x-html="selectedCheck?.dmarc_badge"></span>
                                        </div>
                                    </div>
                                </div>

                                <!-- Why Summary -->
                                <div x-show="selectedCheck?.why_summary">
                                    <h3 class="text-sm font-semibold text-gray-900 mb-3">Analysis</h3>
                                    <div class="p-4 bg-blue-50 border border-blue-200 rounded-lg">
                                        <p class="text-sm text-blue-900" x-text="selectedCheck?.why_summary || 'Detailed analysis coming soon.'"></p>
                                    </div>
                                </div>

                                <!-- Detailed Auth Meta (for app-verified checks) -->
                                <div x-show="selectedCheck?.verified_by_app && selectedCheck?.auth_meta">
                                    <h3 class="text-sm font-semibold text-gray-900 mb-3">Verification Details</h3>
                                    <div class="space-y-3 text-sm">
                                        <!-- Connection Info -->
                                        <div class="p-3 bg-gray-50 rounded-lg">
                                            <h4 class="font-medium text-gray-700 mb-2">Connection Information</h4>
                                            <dl class="space-y-1 text-xs">
                                                <div class="flex justify-between">
                                                    <dt class="text-gray-600">Connecting IP:</dt>
                                                    <dd class="text-gray-900 font-mono" x-text="selectedCheck?.auth_meta?.ip || '—'"></dd>
                                                </div>
                                                <div class="flex justify-between">
                                                    <dt class="text-gray-600">Envelope From:</dt>
                                                    <dd class="text-gray-900 font-mono text-right ml-2 break-all" x-text="selectedCheck?.auth_meta?.mailfrom || '—'"></dd>
                                                </div>
                                                <div class="flex justify-between">
                                                    <dt class="text-gray-600">Header From:</dt>
                                                    <dd class="text-gray-900 font-mono text-right ml-2 break-all" x-text="selectedCheck?.auth_meta?.header_from || '—'"></dd>
                                                </div>
                                            </dl>
                                        </div>

                                        <!-- DKIM Signatures -->
                                        <template x-if="selectedCheck?.auth_meta?.dkim && selectedCheck.auth_meta.dkim.length > 0">
                                            <div class="p-3 bg-gray-50 rounded-lg">
                                                <h4 class="font-medium text-gray-700 mb-2">DKIM Signatures</h4>
                                                <template x-for="(sig, index) in selectedCheck.auth_meta.dkim" :key="index">
                                                    <div class="mb-2 last:mb-0 p-2 bg-white rounded border" :class="sig.pass ? 'border-green-200' : 'border-red-200'">
                                                        <div class="flex items-center justify-between mb-1">
                                                            <span class="text-xs font-mono" x-text="'d=' + sig.d"></span>
                                                            <span class="text-xs px-2 py-0.5 rounded" 
                                                                  :class="sig.pass ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'"
                                                                  x-text="sig.pass ? 'Valid' : 'Invalid'"></span>
                                                        </div>
                                                        <div class="text-xs text-gray-600">
                                                            <span x-text="'Selector: ' + sig.s"></span>
                                                            <span x-show="sig.aligned" class="ml-2 text-green-600">✓ Aligned</span>
                                                            <span x-show="!sig.aligned" class="ml-2 text-amber-600">⚠ Not aligned</span>
                                                        </div>
                                                        <div x-show="sig.reason" class="text-xs text-red-600 mt-1" x-text="sig.reason"></div>
                                                    </div>
                                                </template>
                                            </div>
                                        </template>

                                        <!-- DMARC Policy -->
                                        <template x-if="selectedCheck?.auth_meta?.dmarc">
                                            <div class="p-3 bg-gray-50 rounded-lg">
                                                <h4 class="font-medium text-gray-700 mb-2">DMARC Policy</h4>
                                                <dl class="space-y-1 text-xs">
                                                    <div class="flex justify-between">
                                                        <dt class="text-gray-600">Policy:</dt>
                                                        <dd class="text-gray-900 font-medium" x-text="selectedCheck.auth_meta.dmarc.policy || '—'"></dd>
                                                    </div>
                                                    <template x-if="selectedCheck.auth_meta.dmarc.aligned">
                                                        <div class="flex justify-between">
                                                            <dt class="text-gray-600">SPF Aligned:</dt>
                                                            <dd x-text="selectedCheck.auth_meta.dmarc.aligned.spf ? '✓ Yes' : '✗ No'"
                                                                :class="selectedCheck.auth_meta.dmarc.aligned.spf ? 'text-green-600' : 'text-red-600'"></dd>
                                                        </div>
                                                        <div class="flex justify-between">
                                                            <dt class="text-gray-600">DKIM Aligned:</dt>
                                                            <dd x-text="selectedCheck.auth_meta.dmarc.aligned.dkim ? '✓ Yes' : '✗ No'"
                                                                :class="selectedCheck.auth_meta.dmarc.aligned.dkim ? 'text-green-600' : 'text-red-600'"></dd>
                                                        </div>
                                                    </template>
                                                </dl>
                                            </div>
                                        </template>

                                        <!-- Verification Notes -->
                                        <template x-if="selectedCheck?.auth_meta?.notes && selectedCheck.auth_meta.notes.length > 0">
                                            <div class="p-3 bg-amber-50 border border-amber-200 rounded-lg">
                                                <h4 class="font-medium text-amber-900 mb-2 text-xs">Notes</h4>
                                                <ul class="space-y-1">
                                                    <template x-for="(note, index) in selectedCheck.auth_meta.notes" :key="index">
                                                        <li class="text-xs text-amber-800" x-text="'• ' + note"></li>
                                                    </template>
                                                </ul>
                                            </div>
                                        </template>
                                    </div>
                                </div>

                                <!-- Raw Headers -->
                                <div x-show="selectedCheck?.raw_headers">
                                    <h3 class="text-sm font-semibold text-gray-900 mb-3">Raw Headers</h3>
                                    <div class="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto">
                                        <pre class="text-xs font-mono whitespace-pre-wrap" x-text="selectedCheck?.raw_headers"></pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function deliveryMonitor() {
    return {
        detailsOpen: false,
        selectedCheck: null,
        
        copyAddress(address) {
            navigator.clipboard.writeText(address).then(() => {
                // Show a brief success message
                const btn = event.target.closest('button');
                const originalText = btn.innerHTML;
                btn.innerHTML = '<i data-lucide="check" class="w-4 h-4"></i><span>Copied!</span>';
                lucide.createIcons();
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    lucide.createIcons();
                }, 2000);
            });
        },
        
        showDetails(checkId) {
            // Fetch check details
            fetch(`/api/delivery-checks/${checkId}`)
                .then(response => response.json())
                .then(data => {
                    this.selectedCheck = data;
                    this.detailsOpen = true;
                    this.$nextTick(() => lucide.createIcons());
                })
                .catch(error => {
                    console.error('Error fetching check details:', error);
                    alert('Failed to load check details. Please try again.');
                });
        }
    };
}
</script>

<style>
[x-cloak] { display: none !important; }
</style>
@endsection
