@extends('layouts.app')

@section('page-title', 'DMARC Activity')

@php
    use App\Services\Dmarc\DmarcStatusService;
@endphp

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">DMARC Activity</h1>
            <p class="text-gray-500 mt-1">See who is sending email as your domains</p>
        </div>
    </div>

    <!-- Conditional Top Banner based on overall state -->
    @if($domainsNeedingSetup->count() > 0 && $domainsActive->count() === 0)
        <div class="bg-amber-50 rounded-xl border border-amber-200 p-4">
            <div class="flex items-start gap-3">
                <div class="flex-shrink-0 w-8 h-8 rounded-lg bg-amber-100 flex items-center justify-center">
                    <i data-lucide="settings" class="w-4 h-4 text-amber-600"></i>
                </div>
                <div>
                    <h3 class="font-medium text-gray-900">Set up DMARC reporting to see who is sending on your domains</h3>
                    <p class="text-sm text-gray-600 mt-1">Add your unique RUA address to your DNS to start receiving aggregate reports.</p>
                </div>
            </div>
        </div>
    @elseif($domainsWaitingForReports->count() > 0 && $domainsActive->count() === 0)
        <div class="bg-blue-50 rounded-xl border border-blue-200 p-4">
            <div class="flex items-start gap-3">
                <div class="flex-shrink-0 w-8 h-8 rounded-lg bg-blue-100 flex items-center justify-center">
                    <i data-lucide="clock" class="w-4 h-4 text-blue-600"></i>
                </div>
                <div>
                    <h3 class="font-medium text-gray-900">Configured. First data arrives in 24–48 hours.</h3>
                    <p class="text-sm text-gray-600 mt-1">Mail providers send DMARC reports once per day. No action needed — data will appear automatically.</p>
                </div>
            </div>
        </div>
    @elseif($domainsActive->count() > 0)
        <div class="bg-green-50 rounded-xl border border-green-200 p-4">
            <div class="flex items-start gap-3">
                <div class="flex-shrink-0 w-8 h-8 rounded-lg bg-green-100 flex items-center justify-center">
                    <i data-lucide="check-circle" class="w-4 h-4 text-green-600"></i>
                </div>
                <div>
                    <h3 class="font-medium text-gray-900">{{ $overview['reports_24h'] }} reports received in the last 24 hours</h3>
                    <p class="text-sm text-gray-600 mt-1">{{ $domainsActive->count() }} domain(s) actively receiving DMARC reports.</p>
                </div>
            </div>
        </div>
    @endif

    <!-- Summary Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Domains with New Senders -->
        <div class="bg-white rounded-xl border border-gray-200 p-5">
            <div class="flex items-center gap-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-amber-100 flex items-center justify-center">
                    <i data-lucide="user-plus" class="w-5 h-5 text-amber-600"></i>
                </div>
                <div>
                    <p class="text-sm text-gray-500">New Senders</p>
                    <p class="text-2xl font-bold text-gray-900">{{ $overview['domains_with_new_senders'] }}</p>
                    <p class="text-xs text-gray-400">domains affected</p>
                </div>
            </div>
        </div>

        <!-- Domains with Fail Spikes -->
        <div class="bg-white rounded-xl border border-gray-200 p-5">
            <div class="flex items-center gap-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-red-100 flex items-center justify-center">
                    <i data-lucide="trending-down" class="w-5 h-5 text-red-600"></i>
                </div>
                <div>
                    <p class="text-sm text-gray-500">Fail Spikes</p>
                    <p class="text-2xl font-bold text-gray-900">{{ $overview['domains_with_fail_spikes'] }}</p>
                    <p class="text-xs text-gray-400">domains affected</p>
                </div>
            </div>
        </div>

        <!-- Overall Pass Rate -->
        <div class="bg-white rounded-xl border border-gray-200 p-5">
            <div class="flex items-center gap-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-green-100 flex items-center justify-center">
                    <i data-lucide="shield-check" class="w-5 h-5 text-green-600"></i>
                </div>
                <div>
                    <p class="text-sm text-gray-500">Avg Pass Rate</p>
                    <p class="text-2xl font-bold text-gray-900">{{ $overview['overall_pass_rate'] }}%</p>
                    <p class="text-xs text-gray-400">alignment</p>
                </div>
            </div>
        </div>

        <!-- Reports Received -->
        <div class="bg-white rounded-xl border border-gray-200 p-5">
            <div class="flex items-center gap-3">
                <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center">
                    <i data-lucide="file-text" class="w-5 h-5 text-blue-600"></i>
                </div>
                <div>
                    <p class="text-sm text-gray-500">Reports (24h)</p>
                    <p class="text-2xl font-bold text-gray-900">{{ $overview['reports_24h'] }}</p>
                    <p class="text-xs text-gray-400">received</p>
                </div>
            </div>
        </div>
    </div>

    @if($totalDomains === 0)
        <!-- State: No domains exist -->
        <div class="bg-white rounded-xl border border-gray-200 p-12 text-center">
            <div class="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                <i data-lucide="globe" class="w-8 h-8 text-blue-600"></i>
            </div>
            <h3 class="text-lg font-semibold text-gray-900">No Domains Yet</h3>
            <p class="mt-2 text-gray-500 max-w-md mx-auto">
                Add a domain to start monitoring DMARC activity. Once configured, you'll see who is sending email as your domain.
            </p>
            <a href="{{ route('dashboard.domains') }}" 
               class="mt-6 inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg font-medium transition-colors">
                <i data-lucide="settings" class="w-4 h-4"></i>
                Go to Domains
            </a>
        </div>
    @else
        <!-- All Domains Table with Unified Status -->
        <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-semibold text-gray-900">All Domains</h2>
                <p class="text-sm text-gray-500 mt-1">{{ $totalDomains }} domain(s) — click any domain to view details</p>
            </div>
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Setup Status</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">RUA Address</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Report</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200">
                        @foreach($allDomains as $domain)
                            @php
                                $status = $domain->dmarc_setup_status;
                                $badgeClasses = match($status['badge_color']) {
                                    'green' => 'bg-green-100 text-green-800',
                                    'blue' => 'bg-blue-100 text-blue-800',
                                    'amber' => 'bg-amber-100 text-amber-800',
                                    'gray' => 'bg-gray-100 text-gray-800',
                                    default => 'bg-gray-100 text-gray-800',
                                };
                            @endphp
                            <tr class="hover:bg-gray-50">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <a href="{{ route('dmarc.show', $domain) }}" class="font-medium text-gray-900 hover:text-blue-600">
                                        {{ $domain->domain }}
                                    </a>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $badgeClasses }}">
                                        @if($status['status'] === DmarcStatusService::STATUS_ACTIVE)
                                            <span class="w-1.5 h-1.5 rounded-full bg-green-500 mr-1.5 animate-pulse"></span>
                                        @elseif($status['status'] === DmarcStatusService::STATUS_ENABLED_MXSCAN_WAITING)
                                            <i data-lucide="clock" class="w-3 h-3 mr-1"></i>
                                        @elseif($status['status'] === DmarcStatusService::STATUS_STALE)
                                            <i data-lucide="alert-circle" class="w-3 h-3 mr-1"></i>
                                        @endif
                                        {{ $status['label'] }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex items-center gap-2" x-data="{ copied: false }">
                                        <code class="text-xs text-gray-600 font-mono truncate max-w-[180px]" title="{{ $domain->dmarc_rua_email }}">{{ $domain->dmarc_rua_email }}</code>
                                        <button @click="navigator.clipboard.writeText('{{ $domain->dmarc_rua_email }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                                class="p-1 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded transition-colors"
                                                title="Copy RUA address">
                                            <i data-lucide="copy" class="w-3.5 h-3.5" x-show="!copied"></i>
                                            <i data-lucide="check" class="w-3.5 h-3.5 text-green-600" x-show="copied" x-cloak></i>
                                        </button>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    @if($domain->dmarc_last_report_at)
                                        {{ $domain->dmarc_last_report_at->diffForHumans() }}
                                    @else
                                        <span class="text-gray-400">—</span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right">
                                    <div class="flex items-center justify-end gap-2">
                                        @if($status['status'] !== DmarcStatusService::STATUS_ACTIVE)
                                            <form action="{{ route('dmarc.check-dns', $domain) }}" method="POST" class="inline">
                                                @csrf
                                                <button type="submit" class="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors" title="Check DNS">
                                                    <i data-lucide="refresh-cw" class="w-3 h-3"></i>
                                                    Check DNS
                                                </button>
                                            </form>
                                        @endif
                                        <a href="{{ route('dmarc.show', $domain) }}" 
                                           class="inline-flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors">
                                            View Details
                                        </a>
                                    </div>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </div>

        {{-- Domains Needing Setup Section --}}
        @if($domainsNeedingSetup->count() > 0)
            <!-- How to add DNS record guide -->
            <div class="bg-white rounded-xl border border-gray-200 overflow-hidden" x-data="{ showGuide: false }">
                <button @click="showGuide = !showGuide" class="w-full px-6 py-4 flex items-center justify-between text-left hover:bg-gray-50 transition-colors">
                    <div class="flex items-center gap-3">
                        <div class="flex-shrink-0 w-8 h-8 rounded-full bg-blue-100 flex items-center justify-center">
                            <i data-lucide="help-circle" class="w-4 h-4 text-blue-600"></i>
                        </div>
                        <div>
                            <p class="font-medium text-gray-900">How do I add a DNS record?</p>
                            <p class="text-sm text-gray-500">Step-by-step guide for AWS Route 53, Cloudflare, GoDaddy & more</p>
                        </div>
                    </div>
                    <i data-lucide="chevron-down" class="w-5 h-5 text-gray-400 transition-transform" :class="{ 'rotate-180': showGuide }"></i>
                </button>
                <div x-show="showGuide" x-collapse class="border-t border-gray-200">
                    <div class="p-6 space-y-6">
                        <!-- AWS Route 53 -->
                        <div class="border-b border-gray-100 pb-6">
                            <h4 class="font-medium text-gray-900 mb-3 flex items-center gap-2">
                                <span class="w-6 h-6 bg-orange-100 rounded flex items-center justify-center text-xs font-bold text-orange-600">A</span>
                                AWS Route 53
                            </h4>
                            <ol class="text-sm text-gray-600 space-y-2 ml-8 list-decimal">
                                <li>Go to <strong>Route 53</strong> → <strong>Hosted zones</strong></li>
                                <li>Click on your domain name</li>
                                <li>Click <strong>Create record</strong></li>
                                <li>Record name: <code class="bg-gray-100 px-1 rounded">_dmarc</code></li>
                                <li>Record type: <strong>TXT</strong></li>
                                <li>Value: Copy the DMARC record from below (include the quotes)</li>
                                <li>Click <strong>Create records</strong></li>
                            </ol>
                        </div>

                        <!-- Cloudflare -->
                        <div class="border-b border-gray-100 pb-6">
                            <h4 class="font-medium text-gray-900 mb-3 flex items-center gap-2">
                                <span class="w-6 h-6 bg-orange-100 rounded flex items-center justify-center text-xs font-bold text-orange-600">C</span>
                                Cloudflare
                            </h4>
                            <ol class="text-sm text-gray-600 space-y-2 ml-8 list-decimal">
                                <li>Go to your domain → <strong>DNS</strong> → <strong>Records</strong></li>
                                <li>Click <strong>Add record</strong></li>
                                <li>Type: <strong>TXT</strong></li>
                                <li>Name: <code class="bg-gray-100 px-1 rounded">_dmarc</code></li>
                                <li>Content: Copy the DMARC record from below</li>
                                <li>Click <strong>Save</strong></li>
                            </ol>
                        </div>

                        <!-- GoDaddy -->
                        <div class="border-b border-gray-100 pb-6">
                            <h4 class="font-medium text-gray-900 mb-3 flex items-center gap-2">
                                <span class="w-6 h-6 bg-green-100 rounded flex items-center justify-center text-xs font-bold text-green-600">G</span>
                                GoDaddy
                            </h4>
                            <ol class="text-sm text-gray-600 space-y-2 ml-8 list-decimal">
                                <li>Go to <strong>My Products</strong> → <strong>DNS</strong></li>
                                <li>Click <strong>Add</strong> under Records</li>
                                <li>Type: <strong>TXT</strong></li>
                                <li>Host: <code class="bg-gray-100 px-1 rounded">_dmarc</code></li>
                                <li>TXT Value: Copy the DMARC record from below</li>
                                <li>Click <strong>Save</strong></li>
                            </ol>
                        </div>

                        <!-- Namecheap -->
                        <div>
                            <h4 class="font-medium text-gray-900 mb-3 flex items-center gap-2">
                                <span class="w-6 h-6 bg-red-100 rounded flex items-center justify-center text-xs font-bold text-red-600">N</span>
                                Namecheap
                            </h4>
                            <ol class="text-sm text-gray-600 space-y-2 ml-8 list-decimal">
                                <li>Go to <strong>Domain List</strong> → <strong>Manage</strong> → <strong>Advanced DNS</strong></li>
                                <li>Click <strong>Add New Record</strong></li>
                                <li>Type: <strong>TXT Record</strong></li>
                                <li>Host: <code class="bg-gray-100 px-1 rounded">_dmarc</code></li>
                                <li>Value: Copy the DMARC record from below</li>
                                <li>Click the <strong>✓</strong> to save</li>
                            </ol>
                        </div>

                        <div class="bg-blue-50 rounded-lg p-4 mt-4">
                            <p class="text-sm text-blue-800">
                                <strong>💡 Tip:</strong> DNS changes can take up to 48 hours to propagate worldwide, but usually happen within a few minutes. After adding the record, click "Check DNS" to verify.
                            </p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Domains needing setup - expanded cards -->
            <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-semibold text-gray-900">Setup Required</h2>
                    <p class="text-sm text-gray-500 mt-1">{{ $domainsNeedingSetup->count() }} domain(s) need DMARC configuration</p>
                </div>
                <div class="divide-y divide-gray-200">
                    @foreach($domainsNeedingSetup as $domain)
                        @php
                            $status = $domain->dmarc_setup_status;
                            $isEnabledNotMxscan = $status['status'] === DmarcStatusService::STATUS_ENABLED_NOT_MXSCAN;
                        @endphp
                        <div class="p-6">
                            <div class="flex items-center justify-between mb-4">
                                <div class="flex items-center gap-3">
                                    <div class="flex-shrink-0 w-10 h-10 rounded-full bg-gray-100 flex items-center justify-center">
                                        <i data-lucide="globe" class="w-5 h-5 text-gray-500"></i>
                                    </div>
                                    <div>
                                        <p class="font-semibold text-gray-900">{{ $domain->domain }}</p>
                                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium {{ $isEnabledNotMxscan ? 'bg-amber-100 text-amber-800' : 'bg-gray-100 text-gray-800' }}">
                                            {{ $status['label'] }}
                                        </span>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="bg-gray-50 rounded-lg p-4 space-y-4">
                                @if($isEnabledNotMxscan)
                                    {{-- Scenario: DMARC exists but not sending to MXScan - Smart Update --}}
                                    @if($domain->dmarc_update)
                                        <div class="space-y-3">
                                            <div>
                                                <p class="text-xs text-gray-500 mb-1">Your Current Record</p>
                                                <code class="block px-3 py-2 bg-gray-100 border border-gray-200 rounded-lg text-xs font-mono text-gray-600 break-all">{{ $domain->dmarc_update['current'] }}</code>
                                            </div>
                                            <div>
                                                <p class="text-xs text-gray-500 mb-1"><span class="text-green-600 font-medium">✓ Updated Record</span> — Replace with this:</p>
                                                <div class="flex items-start gap-2" x-data="{ copied: false }">
                                                    <code class="flex-1 block px-3 py-2 bg-green-50 border border-green-200 rounded-lg text-xs font-mono text-gray-800 break-all">{{ $domain->dmarc_update['updated'] }}</code>
                                                    <button @click="navigator.clipboard.writeText('{{ $domain->dmarc_update['updated'] }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                                            class="flex-shrink-0 px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg transition-colors">
                                                        <span x-show="!copied">Copy</span>
                                                        <span x-show="copied" x-cloak>Copied!</span>
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    @else
                                        <div>
                                            <p class="text-sm text-gray-500 mb-2">Add this address to your existing rua</p>
                                            <div class="flex items-start gap-2" x-data="{ copied: false }">
                                                <code class="flex-1 block px-3 py-2 bg-white border border-gray-200 rounded-lg text-sm font-mono text-gray-800 break-all">mailto:{{ $domain->dmarc_rua_email }}</code>
                                                <button @click="navigator.clipboard.writeText('mailto:{{ $domain->dmarc_rua_email }}'); copied = true; setTimeout(() => copied = false, 2000)"
                                                        class="flex-shrink-0 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                                                    <span x-show="!copied">Copy</span>
                                                    <span x-show="copied" x-cloak>Copied!</span>
                                                </button>
                                            </div>
                                        </div>
                                    @endif
                                @else
                                    {{-- Scenario: No DMARC record at all --}}
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
                                            <code class="flex-1 block px-3 py-2 bg-white border border-gray-200 rounded-lg text-sm font-mono text-gray-800 break-all">v=DMARC1; p=quarantine; rua=mailto:{{ $domain->dmarc_rua_email }}; pct=100; adkim=r; aspf=r;</code>
                                            <button @click="navigator.clipboard.writeText('v=DMARC1; p=quarantine; rua=mailto:{{ $domain->dmarc_rua_email }}; pct=100; adkim=r; aspf=r;'); copied = true; setTimeout(() => copied = false, 2000)"
                                                    class="flex-shrink-0 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
                                                <span x-show="!copied">Copy</span>
                                                <span x-show="copied" x-cloak>Copied!</span>
                                            </button>
                                        </div>
                                    </div>
                                @endif
                                
                                <div class="flex items-center gap-3 pt-2">
                                    <form action="{{ route('dmarc.check-dns', $domain) }}" method="POST" class="inline">
                                        @csrf
                                        <button type="submit" class="inline-flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm font-medium rounded-lg transition-colors">
                                            <i data-lucide="check-circle" class="w-4 h-4"></i>
                                            I Added It — Check DNS
                                        </button>
                                    </form>
                                    <a href="{{ route('dmarc.show', $domain) }}" class="text-sm text-gray-500 hover:text-gray-700">View Details</a>
                                </div>
                            </div>
                        </div>
                    @endforeach
                </div>
            </div>
        @endif
    @endif

    @if($overview['total_domains_with_dmarc'] > 0)
        <!-- Domains Needing Attention -->
        <div class="bg-white rounded-xl border border-gray-200 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-semibold text-gray-900">Domains Needing Attention</h2>
                <p class="text-sm text-gray-500 mt-1">Review domains with issues or low pass rates</p>
            </div>

            @if(count($overview['domains_needing_attention']) > 0)
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Pass Rate (24h)</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Change vs 7d</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">New Senders</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Top Issue</th>
                                <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Action</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            @foreach($overview['domains_needing_attention'] as $item)
                                <tr class="hover:bg-gray-50">
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="flex items-center">
                                            <div class="flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center
                                                {{ $item['pass_rate_24h'] >= 95 ? 'bg-green-100 text-green-700' : 
                                                   ($item['pass_rate_24h'] >= 80 ? 'bg-amber-100 text-amber-700' : 'bg-red-100 text-red-700') }}">
                                                <span class="text-xs font-bold">{{ round($item['pass_rate_24h']) }}</span>
                                            </div>
                                            <div class="ml-3">
                                                <p class="font-medium text-gray-900">{{ $item['domain']->domain }}</p>
                                            </div>
                                        </div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="text-sm font-medium {{ $item['pass_rate_24h'] >= 95 ? 'text-green-600' : ($item['pass_rate_24h'] >= 80 ? 'text-amber-600' : 'text-red-600') }}">
                                            {{ $item['pass_rate_24h'] }}%
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        @if($item['change_vs_7d'] > 0)
                                            <span class="inline-flex items-center text-sm text-green-600">
                                                <i data-lucide="trending-up" class="w-4 h-4 mr-1"></i>
                                                +{{ $item['change_vs_7d'] }}%
                                            </span>
                                        @elseif($item['change_vs_7d'] < 0)
                                            <span class="inline-flex items-center text-sm text-red-600">
                                                <i data-lucide="trending-down" class="w-4 h-4 mr-1"></i>
                                                {{ $item['change_vs_7d'] }}%
                                            </span>
                                        @else
                                            <span class="text-sm text-gray-500">—</span>
                                        @endif
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        @if($item['new_senders_7d'] > 0)
                                            <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-amber-100 text-amber-800">
                                                {{ $item['new_senders_7d'] }} new
                                            </span>
                                        @else
                                            <span class="text-sm text-gray-400">—</span>
                                        @endif
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        @if($item['top_issue'])
                                            <span class="text-sm text-gray-700">{{ $item['top_issue'] }}</span>
                                        @else
                                            <span class="text-sm text-gray-400">—</span>
                                        @endif
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-right">
                                        <a href="{{ route('dmarc.show', $item['domain']) }}" 
                                           class="text-blue-600 hover:text-blue-700 text-sm font-medium">
                                            View
                                        </a>
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
            @else
                <div class="px-6 py-12 text-center">
                    <div class="mx-auto w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mb-3">
                        <i data-lucide="check-circle" class="w-6 h-6 text-green-600"></i>
                    </div>
                    <p class="text-gray-600">All domains are healthy!</p>
                    <p class="text-sm text-gray-400 mt-1">No issues detected in the last 24 hours</p>
                </div>
            @endif
        </div>

    @endif

    <!-- What Happens Next + RUA Explainer -->
    <div class="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl border border-blue-200 p-6">
        <div class="flex items-start gap-4">
            <div class="flex-shrink-0 w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center">
                <i data-lucide="info" class="w-5 h-5 text-blue-600"></i>
            </div>
            <div class="flex-1">
                <h3 class="font-semibold text-gray-900">What happens next?</h3>
                <div class="mt-3 grid grid-cols-1 sm:grid-cols-4 gap-4 text-sm">
                    <div class="flex items-start gap-2">
                        <span class="flex-shrink-0 w-6 h-6 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xs font-bold">1</span>
                        <span class="text-gray-600">Add RUA to DNS</span>
                    </div>
                    <div class="flex items-start gap-2">
                        <span class="flex-shrink-0 w-6 h-6 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xs font-bold">2</span>
                        <span class="text-gray-600">Wait for DNS propagation</span>
                    </div>
                    <div class="flex items-start gap-2">
                        <span class="flex-shrink-0 w-6 h-6 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xs font-bold">3</span>
                        <span class="text-gray-600">Provider sends daily report</span>
                    </div>
                    <div class="flex items-start gap-2">
                        <span class="flex-shrink-0 w-6 h-6 rounded-full bg-blue-100 text-blue-600 flex items-center justify-center text-xs font-bold">4</span>
                        <span class="text-gray-600">First data appears in 24–48 hours</span>
                    </div>
                </div>
                
                <!-- RUA Explainer Tooltip -->
                <div class="mt-4 p-3 bg-white/60 rounded-lg border border-blue-100">
                    <p class="text-xs text-gray-600">
                        <strong class="text-gray-700">What is RUA?</strong> 
                        RUA is an email destination for DMARC aggregate reports (XML). MXScan receives these automatically. 
                        <span class="text-blue-700 font-medium">You do NOT send emails to this address</span> and 
                        <span class="text-blue-700 font-medium">you do NOT need to create a mailbox in cPanel</span>.
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
