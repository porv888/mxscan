@extends('layouts.app')

@section('page-title', 'Reports')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Scan Reports</h1>
            <p class="text-gray-600 mt-1">View and analyze your scan history</p>
        </div>
        <a href="{{ route('reports.export', request()->query()) }}" 
           class="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
            <i data-lucide="download" class="w-4 h-4"></i>
            <span>Export CSV</span>
        </a>
    </div>

    <!-- Filters -->
    <div class="bg-white rounded-lg shadow-sm p-4">
        <form method="GET" action="{{ route('reports.index') }}" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <!-- Domain Filter -->
            <div>
                <label for="domain_id" class="block text-sm font-medium text-gray-700 mb-1">Domain</label>
                <select name="domain_id" id="domain_id" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value="">All Domains</option>
                    @foreach($domains as $domain)
                        <option value="{{ $domain->id }}" {{ request('domain_id') == $domain->id ? 'selected' : '' }}>
                            {{ $domain->domain }}
                        </option>
                    @endforeach
                </select>
            </div>

            <!-- Scan Type Filter -->
            <div>
                <label for="scan_type" class="block text-sm font-medium text-gray-700 mb-1">Scan Type</label>
                <select name="scan_type" id="scan_type" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value="">All Types</option>
                    <option value="full" {{ request('scan_type') == 'full' ? 'selected' : '' }}>Complete</option>
                    <option value="dns" {{ request('scan_type') == 'dns' ? 'selected' : '' }}>DNS Only</option>
                    <option value="spf" {{ request('scan_type') == 'spf' ? 'selected' : '' }}>SPF Only</option>
                    <option value="blacklist" {{ request('scan_type') == 'blacklist' ? 'selected' : '' }}>Blacklist Only</option>
                    <option value="delivery" {{ request('scan_type') == 'delivery' ? 'selected' : '' }}>Delivery</option>
                </select>
            </div>

            <!-- Result Filter -->
            <div>
                <label for="result" class="block text-sm font-medium text-gray-700 mb-1">Result</label>
                <select name="result" id="result" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <option value="">All Results</option>
                    <option value="ok" {{ request('result') == 'ok' ? 'selected' : '' }}>OK (≥80)</option>
                    <option value="warn" {{ request('result') == 'warn' ? 'selected' : '' }}>Warning (60-79)</option>
                    <option value="error" {{ request('result') == 'error' ? 'selected' : '' }}>Error (&lt;60)</option>
                </select>
            </div>

            <!-- Date From -->
            <div>
                <label for="date_from" class="block text-sm font-medium text-gray-700 mb-1">Date From</label>
                <input type="date" name="date_from" id="date_from" value="{{ request('date_from') }}"
                       class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>

            <!-- Date To -->
            <div>
                <label for="date_to" class="block text-sm font-medium text-gray-700 mb-1">Date To</label>
                <input type="date" name="date_to" id="date_to" value="{{ request('date_to') }}"
                       class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
            </div>

            <!-- Filter Buttons -->
            <div class="md:col-span-2 lg:col-span-5 flex items-center space-x-2">
                <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm">
                    Apply Filters
                </button>
                <a href="{{ route('reports.index') }}" class="bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-md text-sm">
                    Clear
                </a>
            </div>
        </form>
    </div>

    @if($scans->count() > 0)
        <!-- Reports Table -->
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date/Time</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden lg:table-cell">Blacklist</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden xl:table-cell">SPF Lookups</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Result</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        @foreach($scans as $scan)
                            <tr class="hover:bg-gray-50">
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                    {{ $scan->created_at->format('M j, Y') }}<br>
                                    <span class="text-xs text-gray-500">{{ $scan->created_at->format('g:i A') }}</span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex items-center">
                                        <i data-lucide="globe" class="w-4 h-4 text-gray-400 mr-2"></i>
                                        <span class="text-sm font-medium text-gray-900">{{ $scan->domain->domain }}</span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                        {{ $scan->type === 'full' ? 'bg-purple-100 text-purple-800' : 
                                           ($scan->type === 'blacklist' ? 'bg-red-100 text-red-800' : 
                                           ($scan->type === 'delivery' ? 'bg-green-100 text-green-800' : 'bg-blue-100 text-blue-800')) }}">
                                        {{ $scan->getTypeLabel() }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    @if($scan->score !== null && $scan->hasDnsResults())
                                        <div class="flex items-center">
                                            <span class="text-lg font-bold {{ $scan->score >= 80 ? 'text-green-600' : ($scan->score >= 60 ? 'text-yellow-600' : 'text-red-600') }}">
                                                {{ $scan->score }}
                                            </span>
                                            <span class="text-xs text-gray-500 ml-1">/100</span>
                                        </div>
                                    @else
                                        <span class="text-sm text-gray-400">—</span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap hidden lg:table-cell">
                                    @if($scan->hasBlacklistResults())
                                        @php
                                            $blacklistData = $scan->result_json['blacklist'] ?? null;
                                            $listed = $blacklistData['listed_count'] ?? 0;
                                        @endphp
                                        @if($listed > 0)
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                {{ $listed }} listed
                                            </span>
                                        @else
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                                Clean
                                            </span>
                                        @endif
                                    @else
                                        <span class="text-sm text-gray-400">—</span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap hidden xl:table-cell">
                                    @if($scan->hasSpfResults())
                                        @php
                                            $spfData = $scan->result_json['spf'] ?? null;
                                            $lookups = $spfData['lookups_used'] ?? $spfData['lookupsUsed'] ?? null;
                                        @endphp
                                        @if($lookups !== null)
                                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                                {{ $lookups < 9 ? 'bg-green-100 text-green-800' : ($lookups < 10 ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800') }}">
                                                {{ $lookups }}/10
                                            </span>
                                        @else
                                            <span class="text-sm text-gray-400">—</span>
                                        @endif
                                    @else
                                        <span class="text-sm text-gray-400">—</span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    @php
                                        $statusConfig = [
                                            'finished' => ['bg-green-100', 'text-green-800', 'check-circle'],
                                            'failed' => ['bg-red-100', 'text-red-800', 'alert-circle'],
                                            'running' => ['bg-blue-100', 'text-blue-800', 'loader']
                                        ];
                                        $config = $statusConfig[$scan->status] ?? $statusConfig['running'];
                                    @endphp
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $config[0] }} {{ $config[1] }}">
                                        <i data-lucide="{{ $config[2] }}" class="w-3 h-3 mr-1"></i>
                                        {{ ucfirst($scan->status) }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <a href="{{ route('reports.show', $scan) }}" 
                                       class="text-blue-600 hover:text-blue-900 inline-flex items-center">
                                        <i data-lucide="eye" class="w-4 h-4 mr-1"></i>
                                        View
                                    </a>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div class="px-6 py-4 border-t border-gray-200">
                {{ $scans->links() }}
            </div>
        </div>
    @else
        <!-- Empty State -->
        <div class="bg-white rounded-lg shadow-sm p-8 text-center">
            <div class="mx-auto h-12 w-12 text-gray-400">
                <i data-lucide="file-text" class="h-12 w-12"></i>
            </div>
            <h3 class="mt-4 text-lg font-medium text-gray-900">No scan reports found</h3>
            <p class="mt-2 text-gray-500">
                @if(request()->hasAny(['domain_id', 'scan_type', 'result', 'date_from', 'date_to']))
                    Try adjusting your filters or <a href="{{ route('reports.index') }}" class="text-blue-600 hover:underline">clear all filters</a>.
                @else
                    Run your first scan from the <a href="{{ route('domains') }}" class="text-blue-600 hover:underline">Domains</a> page.
                @endif
            </p>
        </div>
    @endif
</div>
@endsection
