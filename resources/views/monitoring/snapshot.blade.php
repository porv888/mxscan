@extends('layouts.app')

@section('page-title', 'Snapshot Details')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <nav class="flex" aria-label="Breadcrumb">
                <ol class="flex items-center space-x-4">
                    <li>
                        <a href="{{ route('monitoring.snapshots') }}" class="text-gray-400 hover:text-gray-500">
                            <i data-lucide="arrow-left" class="h-5 w-5"></i>
                        </a>
                    </li>
                    <li>
                        <div class="flex items-center">
                            <span class="text-gray-400">/</span>
                            <a href="{{ route('monitoring.snapshots') }}" class="ml-4 text-sm font-medium text-gray-500 hover:text-gray-700">Snapshots</a>
                        </div>
                    </li>
                    <li>
                        <div class="flex items-center">
                            <span class="text-gray-400">/</span>
                            <span class="ml-4 text-sm font-medium text-gray-900">{{ $snapshot->domain->domain }}</span>
                        </div>
                    </li>
                </ol>
            </nav>
        </div>
    </div>

    <!-- Snapshot Overview -->
    <div class="bg-white rounded-lg shadow-sm overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200">
            <div class="flex items-center justify-between">
                <h2 class="text-lg font-semibold text-gray-900">Snapshot Overview</h2>
                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                    {{ ucfirst($snapshot->scan_type) }} Scan
                </span>
            </div>
        </div>
        
        <div class="px-6 py-6">
            <dl class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                <div>
                    <dt class="text-sm font-medium text-gray-500">Domain</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $snapshot->domain->domain }}</dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Scan Type</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ ucfirst($snapshot->scan_type) }}</dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Score</dt>
                    <dd class="mt-1 text-sm text-gray-900">
                        @if($snapshot->score !== null)
                            <span class="text-lg font-semibold">{{ $snapshot->score }}/100</span>
                        @else
                            <span class="text-gray-400">—</span>
                        @endif
                    </dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Created At</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $snapshot->created_at->format('M j, Y \a\t g:i A') }}</dd>
                </div>
            </dl>
        </div>
    </div>

    <!-- DNS Records -->
    <div class="bg-white rounded-lg shadow-sm overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">DNS Records</h3>
        </div>
        
        <div class="px-6 py-6">
            <div class="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
                <!-- MX Records -->
                <div>
                    <dt class="text-sm font-medium text-gray-500 flex items-center">
                        <i data-lucide="mail" class="w-4 h-4 mr-2"></i>
                        MX Records
                    </dt>
                    <dd class="mt-2">
                        @if($snapshot->mx_records)
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                <i data-lucide="check" class="w-3 h-3 mr-1"></i>
                                Present
                            </span>
                        @else
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                <i data-lucide="x" class="w-3 h-3 mr-1"></i>
                                Missing
                            </span>
                        @endif
                    </dd>
                </div>

                <!-- SPF Record -->
                <div>
                    <dt class="text-sm font-medium text-gray-500 flex items-center">
                        <i data-lucide="shield" class="w-4 h-4 mr-2"></i>
                        SPF Record
                    </dt>
                    <dd class="mt-2">
                        @if($snapshot->spf_record)
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                <i data-lucide="check" class="w-3 h-3 mr-1"></i>
                                Present
                            </span>
                        @else
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                <i data-lucide="x" class="w-3 h-3 mr-1"></i>
                                Missing
                            </span>
                        @endif
                    </dd>
                </div>

                <!-- DMARC Record -->
                <div>
                    <dt class="text-sm font-medium text-gray-500 flex items-center">
                        <i data-lucide="shield-check" class="w-4 h-4 mr-2"></i>
                        DMARC Record
                    </dt>
                    <dd class="mt-2">
                        @if($snapshot->dmarc_record)
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                <i data-lucide="check" class="w-3 h-3 mr-1"></i>
                                Present
                            </span>
                        @else
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                <i data-lucide="x" class="w-3 h-3 mr-1"></i>
                                Missing
                            </span>
                        @endif
                    </dd>
                </div>
            </div>

            @if($snapshot->spf_record)
            <div class="mt-6">
                <dt class="text-sm font-medium text-gray-500">SPF Record Value</dt>
                <dd class="mt-1">
                    <div class="bg-gray-50 rounded-lg p-3">
                        <code class="text-sm text-gray-900">{{ $snapshot->spf_record }}</code>
                    </div>
                </dd>
            </div>
            @endif

            @if($snapshot->dmarc_record)
            <div class="mt-6">
                <dt class="text-sm font-medium text-gray-500">DMARC Record Value</dt>
                <dd class="mt-1">
                    <div class="bg-gray-50 rounded-lg p-3">
                        <code class="text-sm text-gray-900">{{ $snapshot->dmarc_record }}</code>
                    </div>
                </dd>
            </div>
            @endif
        </div>
    </div>

    <!-- Blacklist Status -->
    @if($snapshot->blacklist_status)
    <div class="bg-white rounded-lg shadow-sm overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Blacklist Status</h3>
        </div>
        
        <div class="px-6 py-6">
            <div class="flex items-center space-x-4">
                <div>
                    @if($snapshot->blacklist_status === 'clean')
                        <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                            <i data-lucide="shield-check" class="w-4 h-4 mr-2"></i>
                            Clean
                        </span>
                    @else
                        <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800">
                            <i data-lucide="alert-triangle" class="w-4 h-4 mr-2"></i>
                            Listed
                        </span>
                    @endif
                </div>
                @if($snapshot->blacklist_count > 0)
                <div class="text-sm text-gray-600">
                    Listed on {{ $snapshot->blacklist_count }} blacklist{{ $snapshot->blacklist_count > 1 ? 's' : '' }}
                </div>
                @endif
            </div>
        </div>
    </div>
    @endif

    <!-- Raw Data -->
    @if($snapshot->raw_data)
    <div class="bg-white rounded-lg shadow-sm overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Raw Scan Data</h3>
        </div>
        
        <div class="px-6 py-6">
            <div class="bg-gray-50 rounded-lg p-4 overflow-x-auto">
                <pre class="text-xs text-gray-700 whitespace-pre-wrap">{{ json_encode($snapshot->raw_data, JSON_PRETTY_PRINT) }}</pre>
            </div>
        </div>
    </div>
    @endif

    <!-- Actions -->
    <div class="flex justify-between">
        <a href="{{ route('monitoring.snapshots') }}" 
           class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
            <i data-lucide="arrow-left" class="w-4 h-4 mr-2"></i>
            Back to Snapshots
        </a>
        
        <a href="{{ route('dashboard.domains') }}" 
           class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
            <i data-lucide="globe" class="w-4 h-4 mr-2"></i>
            View Domain
        </a>
    </div>
</div>
@endsection
