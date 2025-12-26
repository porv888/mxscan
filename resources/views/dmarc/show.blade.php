@extends('layouts.app')

@section('page-title', 'DMARC Activity - ' . $domain->domain)

@php
    use App\Services\Dmarc\DmarcStatusService;
@endphp

@section('content')
<div class="space-y-6" x-data="{ 
    showSenderDrawer: false, 
    selectedSender: null,
    chartType: 'alignment',
    timeRange: {{ $days }}
}">
    <!-- Header with Back Link -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
            <div class="flex items-center gap-2 text-sm text-gray-500 mb-1">
                <a href="{{ route('dmarc.index') }}" class="hover:text-blue-600">DMARC Activity</a>
                <i data-lucide="chevron-right" class="w-4 h-4"></i>
                <span>{{ $domain->domain }}</span>
            </div>
            <h1 class="text-2xl font-bold text-gray-900">DMARC Visibility</h1>
            <p class="text-gray-500 mt-1">Who is sending email as {{ $domain->domain }}</p>
        </div>
        <div class="flex items-center gap-3">
            @php $latestScan = $domain->scans()->latest()->first(); @endphp
            @if($latestScan)
                <a href="{{ route('scans.show', $latestScan) }}" 
                   class="text-sm text-gray-600 hover:text-gray-900">
                    <i data-lucide="file-text" class="w-4 h-4 inline mr-1"></i>
                    View DNS Report
                </a>
            @endif
        </div>
    </div>

    @php
        $badgeClasses = match($dmarcStatus['badge_color']) {
            'green' => 'bg-green-100 text-green-700',
            'blue' => 'bg-blue-100 text-blue-700',
            'amber' => 'bg-amber-100 text-amber-700',
            'gray' => 'bg-gray-100 text-gray-700',
            default => 'bg-gray-100 text-gray-700',
        };
    @endphp

    <!-- Status Strip with unified status -->
    <div class="bg-white rounded-xl border border-gray-200 p-4">
        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div class="flex items-center gap-4">
                <!-- Status Badge -->
                <div class="flex items-center gap-2 px-3 py-1.5 rounded-full {{ $badgeClasses }}">
                    @if($dmarcStatus['status'] === DmarcStatusService::STATUS_ACTIVE)
                        <span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                    @elseif($dmarcStatus['status'] === DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING)
                        <i data-lucide="clock" class="w-3.5 h-3.5"></i>
                    @elseif($dmarcStatus['status'] === DmarcStatusService::STATUS_STALE)
                        <i data-lucide="alert-circle" class="w-3.5 h-3.5"></i>
                    @endif
                    <span class="text-sm font-medium">{{ $dmarcStatus['label'] }}</span>
                </div>

                <span class="text-sm text-gray-500">{{ $dmarcStatus['helper_text'] }}</span>
            </div>

            <!-- RUA Address + Check DNS Button -->
            <div class="flex items-center gap-3">
                <div class="flex items-center gap-2" x-data="{ copied: false, showTooltip: false }">
                    <span class="text-sm text-gray-500">RUA:</span>
                    <div class="relative">
                        <code class="px-2 py-1 bg-gray-100 rounded text-sm font-mono text-gray-700 cursor-help" 
                              @mouseenter="showTooltip = true" @mouseleave="showTooltip = false">{{ $domain->dmarc_rua_email }}</code>
                        <!-- RUA Tooltip -->
                        <div x-show="showTooltip" x-cloak 
                             class="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-72 p-3 bg-gray-900 text-white text-xs rounded-lg shadow-lg z-50">
                            <p><strong>What is RUA?</strong></p>
                            <p class="mt-1">RUA is an email destination for DMARC aggregate reports (XML). MXScan receives these automatically.</p>
                            <p class="mt-2 text-amber-300">You do NOT send emails to this address and you do NOT need to create a mailbox in cPanel.</p>
                            <div class="absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-1/2 w-2 h-2 bg-gray-900 rotate-45"></div>
                        </div>
                    </div>
                    <button @click="navigator.clipboard.writeText('{{ $domain->dmarc_rua_email }}'); copied = true; setTimeout(() => copied = false, 2000)"
                            class="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded transition-colors">
                        <i data-lucide="copy" class="w-4 h-4" x-show="!copied"></i>
                        <i data-lucide="check" class="w-4 h-4 text-green-600" x-show="copied" x-cloak></i>
                    </button>
                </div>
                @if($dmarcStatus['status'] !== DmarcStatusService::STATUS_ACTIVE)
                    <form action="{{ route('dmarc.check-dns', $domain) }}" method="POST" class="inline">
                        @csrf
                        <button type="submit" class="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors">
                            <i data-lucide="refresh-cw" class="w-3.5 h-3.5"></i>
                            Check DNS
                        </button>
                    </form>
                @endif
            </div>
        </div>
    </div>

    @if($summary['has_data'])
        <!-- Auth Health Summary Cards -->
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <!-- Alignment Pass Rate -->
            <div class="bg-white rounded-xl border border-gray-200 p-5">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500">Alignment Pass Rate</p>
                        <p class="text-3xl font-bold mt-1 {{ $summary['alignment_rate'] >= 95 ? 'text-green-600' : ($summary['alignment_rate'] >= 80 ? 'text-amber-600' : 'text-red-600') }}">
                            {{ $summary['alignment_rate'] }}%
                        </p>
                        <p class="text-xs text-gray-400 mt-1">Last 7 days</p>
                    </div>
                    <div class="flex-shrink-0">
                        @if($comparison['changes']['alignment_rate'] > 0)
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700">
                                <i data-lucide="trending-up" class="w-3 h-3 mr-1"></i>
                                +{{ $comparison['changes']['alignment_rate'] }}%
                            </span>
                        @elseif($comparison['changes']['alignment_rate'] < 0)
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-700">
                                <i data-lucide="trending-down" class="w-3 h-3 mr-1"></i>
                                {{ $comparison['changes']['alignment_rate'] }}%
                            </span>
                        @else
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                                No change
                            </span>
                        @endif
                    </div>
                </div>
            </div>

            <!-- DKIM Pass Rate -->
            <div class="bg-white rounded-xl border border-gray-200 p-5">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500">DKIM Pass Rate</p>
                        <p class="text-3xl font-bold mt-1 {{ $summary['dkim_pass_rate'] >= 95 ? 'text-green-600' : ($summary['dkim_pass_rate'] >= 80 ? 'text-amber-600' : 'text-red-600') }}">
                            {{ $summary['dkim_pass_rate'] }}%
                        </p>
                        <p class="text-xs text-gray-400 mt-1">Last 7 days</p>
                    </div>
                    <div class="flex-shrink-0">
                        @if($comparison['changes']['dkim_pass_rate'] > 0)
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700">
                                <i data-lucide="trending-up" class="w-3 h-3 mr-1"></i>
                                +{{ $comparison['changes']['dkim_pass_rate'] }}%
                            </span>
                        @elseif($comparison['changes']['dkim_pass_rate'] < 0)
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-700">
                                <i data-lucide="trending-down" class="w-3 h-3 mr-1"></i>
                                {{ $comparison['changes']['dkim_pass_rate'] }}%
                            </span>
                        @endif
                    </div>
                </div>
            </div>

            <!-- SPF Pass Rate -->
            <div class="bg-white rounded-xl border border-gray-200 p-5">
                <div class="flex items-center justify-between">
                    <div>
                        <p class="text-sm text-gray-500">SPF Pass Rate</p>
                        <p class="text-3xl font-bold mt-1 {{ $summary['spf_pass_rate'] >= 95 ? 'text-green-600' : ($summary['spf_pass_rate'] >= 80 ? 'text-amber-600' : 'text-red-600') }}">
                            {{ $summary['spf_pass_rate'] }}%
                        </p>
                        <p class="text-xs text-gray-400 mt-1">Last 7 days</p>
                    </div>
                    <div class="flex-shrink-0">
                        @if($comparison['changes']['spf_pass_rate'] > 0)
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-700">
                                <i data-lucide="trending-up" class="w-3 h-3 mr-1"></i>
                                +{{ $comparison['changes']['spf_pass_rate'] }}%
                            </span>
                        @elseif($comparison['changes']['spf_pass_rate'] < 0)
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-red-100 text-red-700">
                                <i data-lucide="trending-down" class="w-3 h-3 mr-1"></i>
                                {{ $comparison['changes']['spf_pass_rate'] }}%
                            </span>
                        @endif
                    </div>
                </div>
            </div>
        </div>

        <!-- Trend Chart -->
        <div class="bg-white rounded-xl border border-gray-200 p-6">
            <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-6">
                <div>
                    <h2 class="text-lg font-semibold text-gray-900">Authentication Trends</h2>
                    <p class="text-sm text-gray-500">Pass rates over time</p>
                </div>
                <div class="flex items-center gap-3">
                    <!-- Chart Type Toggle -->
                    <div class="flex items-center bg-gray-100 rounded-lg p-1">
                        <button @click="chartType = 'alignment'" 
                                :class="chartType === 'alignment' ? 'bg-white shadow text-gray-900' : 'text-gray-500 hover:text-gray-700'"
                                class="px-3 py-1.5 text-sm font-medium rounded-md transition-colors">
                            Alignment
                        </button>
                        <button @click="chartType = 'dkim'" 
                                :class="chartType === 'dkim' ? 'bg-white shadow text-gray-900' : 'text-gray-500 hover:text-gray-700'"
                                class="px-3 py-1.5 text-sm font-medium rounded-md transition-colors">
                            DKIM
                        </button>
                        <button @click="chartType = 'spf'" 
                                :class="chartType === 'spf' ? 'bg-white shadow text-gray-900' : 'text-gray-500 hover:text-gray-700'"
                                class="px-3 py-1.5 text-sm font-medium rounded-md transition-colors">
                            SPF
                        </button>
                    </div>

                    <!-- Time Range -->
                    @if($isPaid)
                        <select class="text-sm border-gray-300 rounded-lg" x-model="timeRange">
                            <option value="7">7 days</option>
                            <option value="30">30 days</option>
                            <option value="90">90 days</option>
                        </select>
                    @else
                        <span class="text-xs text-gray-400">7 days (upgrade for more)</span>
                    @endif
                </div>
            </div>

            <!-- Chart Container -->
            <div class="h-64 relative">
                <canvas id="trendChart"></canvas>
            </div>
        </div>

        <!-- Sender Inventory -->
        <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                    <div>
                        <h2 class="text-lg font-semibold text-gray-900">Sender Inventory</h2>
                        <p class="text-sm text-gray-500">Who is sending email as your domain</p>
                    </div>
                    <div class="flex items-center gap-3">
                        <!-- Filters -->
                        <select class="text-sm border-gray-300 rounded-lg" id="senderStatusFilter">
                            <option value="">All senders</option>
                            <option value="passing">Passing only</option>
                            <option value="failing">Failing only</option>
                            <option value="mixed">Mixed</option>
                        </select>
                        <label class="flex items-center gap-2 text-sm text-gray-600">
                            <input type="checkbox" id="newOnlyFilter" class="rounded border-gray-300 text-blue-600">
                            New only
                        </label>
                        <div class="relative">
                            <input type="text" id="senderSearch" placeholder="Search IP or domain..." 
                                   class="text-sm border-gray-300 rounded-lg pl-8 w-48">
                            <i data-lucide="search" class="w-4 h-4 text-gray-400 absolute left-2.5 top-1/2 -translate-y-1/2"></i>
                        </div>
                    </div>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Volume</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Alignment</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">DKIM</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">SPF</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">First Seen</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200" id="senderTableBody">
                        @forelse($senders as $sender)
                            <tr class="hover:bg-gray-50 cursor-pointer" 
                                @click="selectedSender = {{ json_encode($sender) }}; showSenderDrawer = true">
                                <td class="px-6 py-4">
                                    <div class="flex items-center gap-3">
                                        <div class="flex-shrink-0">
                                            @if($sender['is_new'])
                                                <span class="inline-flex items-center justify-center w-8 h-8 rounded-full bg-amber-100">
                                                    <i data-lucide="sparkles" class="w-4 h-4 text-amber-600"></i>
                                                </span>
                                            @elseif($sender['is_risky'])
                                                <span class="inline-flex items-center justify-center w-8 h-8 rounded-full bg-red-100">
                                                    <i data-lucide="alert-triangle" class="w-4 h-4 text-red-600"></i>
                                                </span>
                                            @else
                                                <span class="inline-flex items-center justify-center w-8 h-8 rounded-full bg-gray-100">
                                                    <i data-lucide="server" class="w-4 h-4 text-gray-500"></i>
                                                </span>
                                            @endif
                                        </div>
                                        <div>
                                            <p class="font-mono text-sm text-gray-900">{{ $sender['source_ip'] }}</p>
                                            @if($sender['ptr_record'])
                                                <p class="text-xs text-gray-500 truncate max-w-xs">{{ $sender['ptr_record'] }}</p>
                                            @elseif($sender['org_name'])
                                                <p class="text-xs text-gray-500">{{ $sender['org_name'] }}</p>
                                            @endif
                                        </div>
                                        @if($sender['is_new'])
                                            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800">
                                                New
                                            </span>
                                        @endif
                                        @if($sender['is_risky'])
                                            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                Risk
                                            </span>
                                        @endif
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="text-sm font-medium text-gray-900">{{ number_format($sender['total_count']) }}</span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex items-center gap-2">
                                        <div class="w-16 h-2 bg-gray-200 rounded-full overflow-hidden">
                                            <div class="h-full rounded-full {{ $sender['alignment_rate'] >= 95 ? 'bg-green-500' : ($sender['alignment_rate'] >= 80 ? 'bg-amber-500' : 'bg-red-500') }}"
                                                 style="width: {{ $sender['alignment_rate'] }}%"></div>
                                        </div>
                                        <span class="text-sm {{ $sender['alignment_rate'] >= 95 ? 'text-green-600' : ($sender['alignment_rate'] >= 80 ? 'text-amber-600' : 'text-red-600') }}">
                                            {{ $sender['alignment_rate'] }}%
                                        </span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="text-sm {{ $sender['dkim_pass_rate'] >= 95 ? 'text-green-600' : ($sender['dkim_pass_rate'] >= 80 ? 'text-amber-600' : 'text-red-600') }}">
                                        {{ $sender['dkim_pass_rate'] }}%
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="text-sm {{ $sender['spf_pass_rate'] >= 95 ? 'text-green-600' : ($sender['spf_pass_rate'] >= 80 ? 'text-amber-600' : 'text-red-600') }}">
                                        {{ $sender['spf_pass_rate'] }}%
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {{ $sender['first_seen_at'] }}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right">
                                    <button class="text-blue-600 hover:text-blue-700 text-sm font-medium">
                                        Details
                                    </button>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="7" class="px-6 py-12 text-center text-gray-500">
                                    No senders found for the selected filters
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>

            @if(!$isPaid && $senders->count() >= 5)
                <div class="px-6 py-4 bg-gradient-to-r from-blue-50 to-indigo-50 border-t border-blue-200">
                    <div class="flex items-center justify-between">
                        <p class="text-sm text-gray-700">
                            <i data-lucide="lock" class="w-4 h-4 inline mr-1"></i>
                            Upgrade to see all senders and extended history
                        </p>
                        <a href="{{ route('pricing') }}" class="text-sm font-medium text-blue-600 hover:text-blue-700">
                            View Plans
                        </a>
                    </div>
                </div>
            @endif
        </div>

        <!-- What Changed Feed -->
        @if($events->count() > 0)
            <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-semibold text-gray-900">What Changed</h2>
                    <p class="text-sm text-gray-500">Recent events and detections</p>
                </div>
                <div class="divide-y divide-gray-200">
                    @foreach($events as $event)
                        <div class="px-6 py-4 flex items-start gap-4">
                            <div class="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center
                                {{ $event->severity === 'critical' ? 'bg-red-100' : ($event->severity === 'warning' ? 'bg-amber-100' : 'bg-blue-100') }}">
                                <i data-lucide="{{ $event->severity_icon }}" class="w-4 h-4 
                                    {{ $event->severity === 'critical' ? 'text-red-600' : ($event->severity === 'warning' ? 'text-amber-600' : 'text-blue-600') }}"></i>
                            </div>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center gap-2">
                                    <p class="font-medium text-gray-900">{{ $event->title }}</p>
                                    <span class="text-xs text-gray-400">{{ $event->created_at->diffForHumans() }}</span>
                                </div>
                                @if($event->description)
                                    <p class="text-sm text-gray-600 mt-1">{{ Str::limit($event->description, 150) }}</p>
                                @endif
                            </div>
                            @if(!$event->acknowledged)
                                <form action="{{ route('dmarc.events.acknowledge', [$domain, $event]) }}" method="POST">
                                    @csrf
                                    <button type="submit" class="text-xs text-gray-400 hover:text-gray-600">
                                        Dismiss
                                    </button>
                                </form>
                            @endif
                        </div>
                    @endforeach
                </div>
            </div>
        @endif

        <!-- Reporting Organizations -->
        @if($reportingOrgs->count() > 0)
            <div class="bg-white rounded-xl border border-gray-200 p-6">
                <h2 class="text-lg font-semibold text-gray-900 mb-4">Reporting Organizations</h2>
                <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
                    @foreach($reportingOrgs as $org)
                        <div class="text-center p-3 rounded-lg bg-gray-50">
                            <p class="font-medium text-gray-900 truncate" title="{{ $org->org_name }}">{{ $org->org_name }}</p>
                            <p class="text-sm text-gray-500">{{ number_format($org->total_volume) }} emails</p>
                            <p class="text-xs text-gray-400">{{ $org->report_count }} reports</p>
                        </div>
                    @endforeach
                </div>
            </div>
        @endif

        <!-- Upload Section -->
        @if($isPaid)
            <div class="bg-white rounded-xl border border-gray-200 p-6">
                <h2 class="text-lg font-semibold text-gray-900 mb-2">Manual Upload</h2>
                <p class="text-sm text-gray-500 mb-4">Upload DMARC aggregate report files for backfill or testing</p>
                <form action="{{ route('dmarc.upload', $domain) }}" method="POST" enctype="multipart/form-data" class="flex items-center gap-4">
                    @csrf
                    <input type="file" name="report_file" accept=".xml,.zip,.gz" 
                           class="text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100">
                    <button type="submit" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-lg transition-colors">
                        Upload
                    </button>
                </form>
            </div>
        @endif

    @else
        <!-- No Data State - Setup Instructions -->
        <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div class="p-6 border-b border-gray-200 {{ $dmarcStatus['status'] === 'enabled_mxscan_waiting' ? 'bg-gradient-to-r from-blue-50 to-indigo-50' : 'bg-gradient-to-r from-amber-50 to-orange-50' }}">
                <div class="flex items-start gap-4">
                    <div class="flex-shrink-0 w-12 h-12 rounded-lg {{ $dmarcStatus['status'] === 'enabled_mxscan_waiting' ? 'bg-blue-100' : 'bg-amber-100' }} flex items-center justify-center">
                        @if($dmarcStatus['status'] === 'enabled_mxscan_waiting')
                            <i data-lucide="clock" class="w-6 h-6 text-blue-600"></i>
                        @else
                            <i data-lucide="settings" class="w-6 h-6 text-amber-600"></i>
                        @endif
                    </div>
                    <div>
                        @if($dmarcStatus['status'] === 'enabled_mxscan_waiting')
                            <h3 class="text-lg font-semibold text-gray-900">Waiting for First Report</h3>
                            <p class="text-sm text-gray-600 mt-1">DNS configured correctly. Reports usually arrive within 24–48 hours.</p>
                        @elseif($dmarcStatus['status'] === 'enabled_not_mxscan')
                            <h3 class="text-lg font-semibold text-gray-900">Add MXScan to Your DMARC Record</h3>
                            <p class="text-sm text-gray-600 mt-1">Your domain has DMARC, but reports aren't sent to MXScan.</p>
                        @else
                            <h3 class="text-lg font-semibold text-gray-900">Enable DMARC Reporting</h3>
                            <p class="text-sm text-gray-600 mt-1">Add a DMARC record to start receiving aggregate reports.</p>
                        @endif
                    </div>
                </div>
            </div>

            <div class="p-6 space-y-4">
                @if($dmarcStatus['status'] === 'enabled_mxscan_waiting')
                    {{-- Waiting state - just show info --}}
                    <div class="bg-blue-50 rounded-lg p-4">
                        <p class="text-sm text-blue-800">
                            <strong>No action needed.</strong> Providers send reports automatically once per day. You don't need to send test emails or create a mailbox.
                        </p>
                    </div>
                @elseif($dmarcStatus['status'] === 'enabled_not_mxscan')
                    {{-- Has DMARC but not MXScan RUA - Show smart update --}}
                    @if(isset($dmarcUpdate) && $dmarcUpdate)
                        <div class="space-y-4">
                            {{-- Current Record --}}
                            <div>
                                <p class="text-sm text-gray-500 mb-2">Your Current DMARC Record</p>
                                <code class="block px-3 py-2 bg-gray-100 border border-gray-200 rounded-lg text-sm font-mono text-gray-600 break-all">{{ $dmarcUpdate['current'] }}</code>
                            </div>
                            
                            {{-- Updated Record --}}
                            <div>
                                <p class="text-sm text-gray-500 mb-2">
                                    <span class="text-green-600 font-medium">✓ Updated Record</span> — Replace your current record with this:
                                </p>
                                <div class="flex items-start gap-2" x-data="{ copied: false }">
                                    <code class="flex-1 block px-3 py-2 bg-green-50 border border-green-200 rounded-lg text-sm font-mono text-gray-800 break-all">{{ $dmarcUpdate['updated'] }}</code>
                                    <button @click="navigator.clipboard.writeText('{{ $dmarcUpdate['updated'] }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                            class="flex-shrink-0 px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg transition-colors">
                                        <span x-show="!copied">Copy</span>
                                        <span x-show="copied" x-cloak>Copied!</span>
                                    </button>
                                </div>
                            </div>
                            
                            <p class="text-xs text-gray-500">This preserves your existing policy settings and adds MXScan as an additional report recipient.</p>
                        </div>
                    @else
                        {{-- Fallback if no scan data available --}}
                        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
                            <div>
                                <p class="text-gray-500 mb-1">Record Type</p>
                                <p class="font-mono font-medium text-gray-900">TXT</p>
                            </div>
                            <div>
                                <p class="text-gray-500 mb-1">Host / Name</p>
                                <p class="font-mono font-medium text-gray-900">_dmarc</p>
                            </div>
                            <div>
                                <p class="text-gray-500 mb-1">Action</p>
                                <p class="font-medium text-amber-600">Update existing record</p>
                            </div>
                        </div>

                        <div>
                            <p class="text-sm text-gray-500 mb-2">Add this address to your existing rua (comma-separate if needed)</p>
                            <div class="flex items-start gap-2" x-data="{ copied: false }">
                                <code class="flex-1 block px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm font-mono text-gray-800 break-all">mailto:{{ $domain->dmarc_rua_email }}</code>
                                <button @click="navigator.clipboard.writeText('mailto:{{ $domain->dmarc_rua_email }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                        class="flex-shrink-0 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                                    <span x-show="!copied">Copy</span>
                                    <span x-show="copied" x-cloak>Copied!</span>
                                </button>
                            </div>
                        </div>
                    @endif
                @else
                    {{-- No DMARC at all --}}
                    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
                        <div>
                            <p class="text-gray-500 mb-1">Record Type</p>
                            <p class="font-mono font-medium text-gray-900">TXT</p>
                        </div>
                        <div>
                            <p class="text-gray-500 mb-1">Host / Name</p>
                            <p class="font-mono font-medium text-gray-900">_dmarc</p>
                        </div>
                        <div>
                            <p class="text-gray-500 mb-1">TTL</p>
                            <p class="font-mono font-medium text-gray-900">3600 (or default)</p>
                        </div>
                    </div>

                    <div>
                        <p class="text-sm text-gray-500 mb-2">Value / Content</p>
                        <div class="flex items-start gap-2" x-data="{ copied: false }">
                            <code class="flex-1 block px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg text-sm font-mono text-gray-800 break-all">v=DMARC1; p=quarantine; rua=mailto:{{ $domain->dmarc_rua_email }}; pct=100; adkim=r; aspf=r;</code>
                            <button @click="navigator.clipboard.writeText('v=DMARC1; p=quarantine; rua=mailto:{{ $domain->dmarc_rua_email }}; pct=100; adkim=r; aspf=r;'); copied = true; setTimeout(() => copied = false, 2000)"
                                    class="flex-shrink-0 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                                <span x-show="!copied">Copy</span>
                                <span x-show="copied" x-cloak>Copied!</span>
                            </button>
                        </div>
                    </div>
                @endif

                @if($dmarcStatus['status'] !== 'enabled_mxscan_waiting')
                    <div class="flex items-center gap-3 pt-2">
                        <form action="{{ route('dmarc.check-dns', $domain) }}" method="POST" class="inline">
                            @csrf
                            <button type="submit" class="inline-flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-lg transition-colors">
                                <i data-lucide="check-circle" class="w-4 h-4"></i>
                                I Added It — Check DNS
                            </button>
                        </form>
                    </div>
                @endif

                <div class="bg-gray-50 rounded-lg p-4 text-sm text-gray-600 space-y-1">
                    <p><i data-lucide="info" class="w-4 h-4 inline mr-1"></i> <strong>No test email needed</strong> — providers send reports automatically.</p>
                    <p><i data-lucide="info" class="w-4 h-4 inline mr-1"></i> <strong>No mailbox needed</strong> — MXScan hosts this address.</p>
                </div>
            </div>
        </div>

        <!-- Common Questions Accordion -->
        <div class="bg-white rounded-xl border border-gray-200 p-6" x-data="{ open: false }">
            <button @click="open = !open" class="flex items-center justify-between w-full text-left">
                <h3 class="font-semibold text-gray-900">Common Questions</h3>
                <i data-lucide="chevron-down" class="w-5 h-5 text-gray-400 transition-transform" :class="{ 'rotate-180': open }"></i>
            </button>
            <div x-show="open" x-collapse class="mt-4 space-y-4 text-sm">
                <div class="border-b border-gray-100 pb-3">
                    <p class="font-medium text-gray-900">Do I need to send a test email to that address?</p>
                    <p class="text-gray-600 mt-1">No. DMARC aggregate reports are sent automatically by email providers (Google, Microsoft, Yahoo, etc.) once per day. You don't send anything to the RUA address.</p>
                </div>
                <div class="border-b border-gray-100 pb-3">
                    <p class="font-medium text-gray-900">Do I need to create a mailbox in cPanel?</p>
                    <p class="text-gray-600 mt-1">No. MXScan hosts the RUA mailbox at mxscan.me. We receive and process the reports automatically.</p>
                </div>
                <div class="border-b border-gray-100 pb-3">
                    <p class="font-medium text-gray-900">Where do reports go?</p>
                    <p class="text-gray-600 mt-1">Reports are sent to your unique RUA address ({{ $domain->dmarc_rua_email }}). MXScan receives them, parses the XML, and displays the data on this page.</p>
                </div>
                <div>
                    <p class="font-medium text-gray-900">How long until I see data?</p>
                    <p class="text-gray-600 mt-1">After DNS propagation (usually minutes, up to 48 hours), providers will start including your RUA in their daily report cycle. First data typically appears within 24–48 hours.</p>
                </div>
            </div>
        </div>
    @endif

    <!-- Sender Detail Drawer -->
    <div x-show="showSenderDrawer" 
         x-transition:enter="transition ease-out duration-300"
         x-transition:enter-start="opacity-0"
         x-transition:enter-end="opacity-100"
         x-transition:leave="transition ease-in duration-200"
         x-transition:leave-start="opacity-100"
         x-transition:leave-end="opacity-0"
         class="fixed inset-0 bg-black bg-opacity-50 z-40"
         @click="showSenderDrawer = false"
         x-cloak></div>

    <div x-show="showSenderDrawer"
         x-transition:enter="transition ease-out duration-300"
         x-transition:enter-start="translate-x-full"
         x-transition:enter-end="translate-x-0"
         x-transition:leave="transition ease-in duration-200"
         x-transition:leave-start="translate-x-0"
         x-transition:leave-end="translate-x-full"
         class="fixed right-0 top-0 h-full w-full max-w-md bg-white shadow-xl z-50 overflow-y-auto"
         x-cloak>
        <template x-if="selectedSender">
            <div class="p-6">
                <div class="flex items-center justify-between mb-6">
                    <h3 class="text-lg font-semibold text-gray-900">Sender Details</h3>
                    <button @click="showSenderDrawer = false" class="p-2 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg">
                        <i data-lucide="x" class="w-5 h-5"></i>
                    </button>
                </div>

                <!-- Sender Info -->
                <div class="space-y-6">
                    <div>
                        <p class="text-sm text-gray-500">Source IP</p>
                        <p class="font-mono text-lg text-gray-900" x-text="selectedSender.source_ip"></p>
                        <p class="text-sm text-gray-500" x-text="selectedSender.ptr_record || selectedSender.org_name || 'Unknown'"></p>
                    </div>

                    <div class="grid grid-cols-2 gap-4">
                        <div class="p-4 bg-gray-50 rounded-lg">
                            <p class="text-sm text-gray-500">Total Volume</p>
                            <p class="text-2xl font-bold text-gray-900" x-text="selectedSender.total_count?.toLocaleString()"></p>
                        </div>
                        <div class="p-4 bg-gray-50 rounded-lg">
                            <p class="text-sm text-gray-500">Alignment Rate</p>
                            <p class="text-2xl font-bold" 
                               :class="selectedSender.alignment_rate >= 95 ? 'text-green-600' : (selectedSender.alignment_rate >= 80 ? 'text-amber-600' : 'text-red-600')"
                               x-text="selectedSender.alignment_rate + '%'"></p>
                        </div>
                    </div>

                    <div class="space-y-3">
                        <div class="flex items-center justify-between py-2 border-b border-gray-100">
                            <span class="text-sm text-gray-500">DKIM Pass Rate</span>
                            <span class="text-sm font-medium" 
                                  :class="selectedSender.dkim_pass_rate >= 95 ? 'text-green-600' : (selectedSender.dkim_pass_rate >= 80 ? 'text-amber-600' : 'text-red-600')"
                                  x-text="selectedSender.dkim_pass_rate + '%'"></span>
                        </div>
                        <div class="flex items-center justify-between py-2 border-b border-gray-100">
                            <span class="text-sm text-gray-500">SPF Pass Rate</span>
                            <span class="text-sm font-medium"
                                  :class="selectedSender.spf_pass_rate >= 95 ? 'text-green-600' : (selectedSender.spf_pass_rate >= 80 ? 'text-amber-600' : 'text-red-600')"
                                  x-text="selectedSender.spf_pass_rate + '%'"></span>
                        </div>
                        <div class="flex items-center justify-between py-2 border-b border-gray-100">
                            <span class="text-sm text-gray-500">First Seen</span>
                            <span class="text-sm text-gray-900" x-text="selectedSender.first_seen_at"></span>
                        </div>
                        <div class="flex items-center justify-between py-2 border-b border-gray-100">
                            <span class="text-sm text-gray-500">Last Seen</span>
                            <span class="text-sm text-gray-900" x-text="selectedSender.last_seen_at"></span>
                        </div>
                        <template x-if="selectedSender.dkim_domain">
                            <div class="flex items-center justify-between py-2 border-b border-gray-100">
                                <span class="text-sm text-gray-500">DKIM Domain</span>
                                <span class="text-sm text-gray-900" x-text="selectedSender.dkim_domain"></span>
                            </div>
                        </template>
                        <template x-if="selectedSender.spf_domain">
                            <div class="flex items-center justify-between py-2 border-b border-gray-100">
                                <span class="text-sm text-gray-500">SPF Domain</span>
                                <span class="text-sm text-gray-900" x-text="selectedSender.spf_domain"></span>
                            </div>
                        </template>
                    </div>

                    <!-- Disposition Breakdown -->
                    <div>
                        <p class="text-sm font-medium text-gray-700 mb-3">Disposition Breakdown</p>
                        <div class="space-y-2">
                            <div class="flex items-center gap-3">
                                <div class="w-3 h-3 rounded-full bg-green-500"></div>
                                <span class="text-sm text-gray-600 flex-1">None (delivered)</span>
                                <span class="text-sm font-medium text-gray-900" x-text="selectedSender.disposition_breakdown?.none?.toLocaleString() || 0"></span>
                            </div>
                            <div class="flex items-center gap-3">
                                <div class="w-3 h-3 rounded-full bg-amber-500"></div>
                                <span class="text-sm text-gray-600 flex-1">Quarantine</span>
                                <span class="text-sm font-medium text-gray-900" x-text="selectedSender.disposition_breakdown?.quarantine?.toLocaleString() || 0"></span>
                            </div>
                            <div class="flex items-center gap-3">
                                <div class="w-3 h-3 rounded-full bg-red-500"></div>
                                <span class="text-sm text-gray-600 flex-1">Reject</span>
                                <span class="text-sm font-medium text-gray-900" x-text="selectedSender.disposition_breakdown?.reject?.toLocaleString() || 0"></span>
                            </div>
                        </div>
                    </div>

                    <!-- Suggested Fix -->
                    <template x-if="selectedSender.suggested_fix">
                        <div class="p-4 bg-blue-50 rounded-lg border border-blue-200">
                            <div class="flex items-start gap-3">
                                <i data-lucide="lightbulb" class="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5"></i>
                                <div>
                                    <p class="text-sm font-medium text-blue-900">Suggested Action</p>
                                    <p class="text-sm text-blue-700 mt-1" x-text="selectedSender.suggested_fix"></p>
                                </div>
                            </div>
                        </div>
                    </template>
                </div>
            </div>
        </template>
    </div>
</div>

<!-- Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function() {
    const ctx = document.getElementById('trendChart');
    if (!ctx) return;

    const trendData = @json($trends);
    
    const chart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: trendData.map(d => d.date_label),
            datasets: [{
                label: 'Alignment',
                data: trendData.map(d => d.alignment_rate),
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.3,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return context.parsed.y + '% pass rate';
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: false,
                    min: 0,
                    max: 100,
                    ticks: {
                        callback: function(value) {
                            return value + '%';
                        }
                    }
                }
            }
        }
    });

    // Update chart based on type selection
    document.addEventListener('alpine:init', () => {
        Alpine.effect(() => {
            const chartType = Alpine.store('chartType') || 'alignment';
            const dataKey = chartType === 'alignment' ? 'alignment_rate' : 
                           (chartType === 'dkim' ? 'dkim_pass_rate' : 'spf_pass_rate');
            const color = chartType === 'alignment' ? '#3b82f6' : 
                         (chartType === 'dkim' ? '#10b981' : '#f59e0b');
            
            chart.data.datasets[0].data = trendData.map(d => d[dataKey]);
            chart.data.datasets[0].borderColor = color;
            chart.data.datasets[0].backgroundColor = color.replace(')', ', 0.1)').replace('rgb', 'rgba');
            chart.update();
        });
    });
});
</script>
@endsection
