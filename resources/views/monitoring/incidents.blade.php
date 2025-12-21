@extends('layouts.app')

@section('page-title', 'Security Incidents')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Security Incidents</h1>
            <p class="text-gray-600 mt-1">Monitor security incidents across your domains</p>
        </div>
    </div>

    <!-- Filters -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <form method="GET" class="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
                <label for="severity" class="block text-sm font-medium text-gray-700">Severity</label>
                <select name="severity" id="severity" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
                    <option value="">All Severities</option>
                    <option value="incident" {{ request('severity') === 'incident' ? 'selected' : '' }}>Incident</option>
                    <option value="warning" {{ request('severity') === 'warning' ? 'selected' : '' }}>Warning</option>
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

            <div>
                <label for="from" class="block text-sm font-medium text-gray-700">From Date</label>
                <input type="date" name="from" id="from" value="{{ request('from') }}" 
                       class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500">
            </div>

            <div class="flex items-end">
                <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
                    Filter
                </button>
            </div>
        </form>
    </div>

    <!-- Incidents List -->
    @if($incidents->count() > 0)
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-semibold text-gray-900">Incidents ({{ $incidents->total() }})</h2>
            </div>
            
            <div class="divide-y divide-gray-200">
                @foreach($incidents as $incident)
                    <div class="p-6 hover:bg-gray-50">
                        <div class="flex items-start justify-between">
                            <div class="flex-1">
                                <div class="flex items-center space-x-3">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                        @if($incident->severity === 'incident') bg-red-100 text-red-800
                                        @elseif($incident->severity === 'warning') bg-yellow-100 text-yellow-800
                                        @else bg-gray-100 text-gray-800 @endif">
                                        @if($incident->severity === 'incident')
                                            <i data-lucide="alert-triangle" class="w-3 h-3 mr-1"></i>
                                        @elseif($incident->severity === 'warning')
                                            <i data-lucide="alert-circle" class="w-3 h-3 mr-1"></i>
                                        @else
                                            <i data-lucide="info" class="w-3 h-3 mr-1"></i>
                                        @endif
                                        {{ ucfirst($incident->severity) }}
                                    </span>
                                    <span class="text-sm font-medium text-gray-700">{{ str_replace('_', ' ', ucwords($incident->type ?? 'Unknown', '_')) }}</span>
                                    <span class="text-sm text-gray-500">{{ $incident->domain->domain }}</span>
                                    <span class="text-sm text-gray-500">{{ ($incident->occurred_at ?? $incident->created_at)->diffForHumans() }}</span>
                                </div>
                                <p class="mt-2 text-gray-900">{{ $incident->message }}</p>
                            </div>
                            <div class="ml-4">
                                <a href="{{ route('monitoring.incidents.show', $incident) }}" 
                                   class="text-blue-600 hover:text-blue-500 text-sm font-medium">
                                    View Details
                                </a>
                            </div>
                        </div>
                    </div>
                @endforeach
            </div>

            <!-- Pagination -->
            <div class="px-6 py-4 border-t border-gray-200">
                {{ $incidents->links() }}
            </div>
        </div>
    @else
        <div class="bg-white rounded-lg shadow-sm p-12 text-center">
            <i data-lucide="shield-check" class="mx-auto h-12 w-12 text-gray-400"></i>
            <h3 class="mt-4 text-lg font-medium text-gray-900">No incidents found</h3>
            <p class="mt-2 text-gray-500">
                @if(request()->hasAny(['severity', 'domain_id', 'from', 'to']))
                    No incidents match your current filters. Try adjusting your search criteria.
                @else
                    Great! No security incidents have been detected for your domains.
                @endif
            </p>
            @if(request()->hasAny(['severity', 'domain_id', 'from', 'to']))
                <a href="{{ route('monitoring.incidents') }}" class="mt-4 inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-blue-700 bg-blue-100 hover:bg-blue-200">
                    Clear Filters
                </a>
            @endif
        </div>
    @endif
</div>
@endsection
