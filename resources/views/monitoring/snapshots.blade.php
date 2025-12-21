@extends('layouts.app')

@section('page-title', 'Scan Snapshots')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Scan Snapshots</h1>
            <p class="text-gray-600 mt-1">View historical scan data and changes over time</p>
        </div>
    </div>

    <!-- Filters -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <form method="GET" class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
                <label for="scan_type" class="block text-sm font-medium text-gray-700">Scan Type</label>
                <select name="scan_type" id="scan_type" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                    <option value="">All Types</option>
                    <option value="full" {{ request('scan_type') === 'full' ? 'selected' : '' }}>Full Scan</option>
                    <option value="dns" {{ request('scan_type') === 'dns' ? 'selected' : '' }}>DNS Only</option>
                    <option value="spf" {{ request('scan_type') === 'spf' ? 'selected' : '' }}>SPF Only</option>
                    <option value="blacklist" {{ request('scan_type') === 'blacklist' ? 'selected' : '' }}>Blacklist Only</option>
                </select>
            </div>

            <div>
                <label for="domain_id" class="block text-sm font-medium text-gray-700">Domain</label>
                <select name="domain_id" id="domain_id" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                    <option value="">All Domains</option>
                    @foreach($domains as $domain)
                        <option value="{{ $domain->id }}" {{ request('domain_id') == $domain->id ? 'selected' : '' }}>
                            {{ $domain->domain }}
                        </option>
                    @endforeach
                </select>
            </div>

            <div class="flex items-end">
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                    Filter
                </button>
            </div>
        </form>
    </div>

    <!-- Snapshots List -->
    @if($snapshots->count() > 0)
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-semibold text-gray-900">Snapshots ({{ $snapshots->total() }})</h2>
            </div>
            
            <div class="overflow-x-auto">
                <table class="w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Score</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Records</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        @foreach($snapshots as $snapshot)
                            <tr class="hover:bg-gray-50">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="text-sm font-medium text-gray-900">{{ $snapshot->domain->domain }}</div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                        {{ ucfirst($snapshot->scan_type) }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    @if($snapshot->score !== null)
                                        <div class="text-sm text-gray-900">{{ $snapshot->score }}/100</div>
                                    @else
                                        <div class="text-sm text-gray-400">—</div>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex space-x-2">
                                        @if($snapshot->mx_records)
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">MX</span>
                                        @endif
                                        @if($snapshot->spf_record)
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">SPF</span>
                                        @endif
                                        @if($snapshot->dmarc_record)
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">DMARC</span>
                                        @endif
                                        @if($snapshot->blacklist_status === 'clean')
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">Clean</span>
                                        @elseif($snapshot->blacklist_status === 'listed')
                                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-100 text-red-800">Listed</span>
                                        @endif
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {{ $snapshot->created_at->format('M j, Y g:i A') }}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <a href="{{ route('monitoring.snapshots.show', $snapshot) }}" 
                                       class="text-blue-600 hover:text-blue-500">View</a>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <div class="px-6 py-4 border-t border-gray-200">
                {{ $snapshots->links() }}
            </div>
        </div>
    @else
        <div class="bg-white rounded-lg shadow-sm p-12 text-center">
            <i data-lucide="camera" class="mx-auto h-12 w-12 text-gray-400"></i>
            <h3 class="mt-4 text-lg font-medium text-gray-900">No snapshots found</h3>
            <p class="mt-2 text-gray-500">
                @if(request()->hasAny(['scan_type', 'domain_id']))
                    No snapshots match your current filters. Try adjusting your search criteria.
                @else
                    Snapshots will appear here after you run scans on your domains.
                @endif
            </p>
            @if(request()->hasAny(['scan_type', 'domain_id']))
                <a href="{{ route('monitoring.snapshots') }}" class="mt-4 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200">
                    Clear Filters
                </a>
            @endif
        </div>
    @endif
</div>
@endsection
