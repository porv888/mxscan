@extends('layouts.app')

@section('page-title', 'Incident Details')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <nav class="flex" aria-label="Breadcrumb">
                <ol class="flex items-center space-x-4">
                    <li>
                        <a href="{{ route('monitoring.incidents') }}" class="text-gray-400 hover:text-gray-500">
                            <i data-lucide="arrow-left" class="h-5 w-5"></i>
                        </a>
                    </li>
                    <li>
                        <div class="flex items-center">
                            <span class="text-gray-400">/</span>
                            <a href="{{ route('monitoring.incidents') }}" class="ml-4 text-sm font-medium text-gray-500 hover:text-gray-700">Incidents</a>
                        </div>
                    </li>
                    <li>
                        <div class="flex items-center">
                            <span class="text-gray-400">/</span>
                            <span class="ml-4 text-sm font-medium text-gray-900">{{ $incident->title }}</span>
                        </div>
                    </li>
                </ol>
            </nav>
        </div>
    </div>

    <!-- Incident Details -->
    <div class="bg-white rounded-lg shadow-sm overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200">
            <div class="flex items-center justify-between">
                <h2 class="text-lg font-semibold text-gray-900">Incident Details</h2>
                <span class="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium
                    @if($incident->severity === 'critical') bg-red-100 text-red-800
                    @elseif($incident->severity === 'warning') bg-yellow-100 text-yellow-800
                    @else bg-blue-100 text-blue-800 @endif">
                    @if($incident->severity === 'critical')
                        <i data-lucide="alert-triangle" class="w-4 h-4 mr-2"></i>
                    @elseif($incident->severity === 'warning')
                        <i data-lucide="alert-circle" class="w-4 h-4 mr-2"></i>
                    @else
                        <i data-lucide="info" class="w-4 h-4 mr-2"></i>
                    @endif
                    {{ ucfirst($incident->severity) }}
                </span>
            </div>
        </div>
        
        <div class="px-6 py-6">
            <dl class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                <div>
                    <dt class="text-sm font-medium text-gray-500">Title</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $incident->title }}</dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Domain</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $incident->domain->domain }}</dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Detected At</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $incident->created_at->format('M j, Y \a\t g:i A') }}</dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Time Ago</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $incident->created_at->diffForHumans() }}</dd>
                </div>
                
                <div class="sm:col-span-2">
                    <dt class="text-sm font-medium text-gray-500">Message</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $incident->message }}</dd>
                </div>
                
                @if($incident->metadata)
                <div class="sm:col-span-2">
                    <dt class="text-sm font-medium text-gray-500">Additional Details</dt>
                    <dd class="mt-1">
                        <div class="bg-gray-50 rounded-lg p-4">
                            <pre class="text-xs text-gray-700 whitespace-pre-wrap">{{ json_encode($incident->metadata, JSON_PRETTY_PRINT) }}</pre>
                        </div>
                    </dd>
                </div>
                @endif
            </dl>
        </div>
    </div>

    <!-- Related Snapshot -->
    @if($incident->snapshot)
    <div class="bg-white rounded-lg shadow-sm overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200">
            <h3 class="text-lg font-semibold text-gray-900">Related Scan Snapshot</h3>
        </div>
        
        <div class="px-6 py-6">
            <dl class="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
                <div>
                    <dt class="text-sm font-medium text-gray-500">Scan Type</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ ucfirst($incident->snapshot->scan_type) }}</dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Score</dt>
                    <dd class="mt-1 text-sm text-gray-900">
                        @if($incident->snapshot->score !== null)
                            {{ $incident->snapshot->score }}/100
                        @else
                            —
                        @endif
                    </dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Snapshot Created</dt>
                    <dd class="mt-1 text-sm text-gray-900">{{ $incident->snapshot->created_at->format('M j, Y \a\t g:i A') }}</dd>
                </div>
                
                <div>
                    <dt class="text-sm font-medium text-gray-500">Actions</dt>
                    <dd class="mt-1">
                        <a href="{{ route('monitoring.snapshots.show', $incident->snapshot) }}" 
                           class="text-blue-600 hover:text-blue-500 text-sm font-medium">
                            View Full Snapshot
                        </a>
                    </dd>
                </div>
            </dl>
        </div>
    </div>
    @endif

    <!-- Actions -->
    <div class="flex justify-between">
        <a href="{{ route('monitoring.incidents') }}" 
           class="inline-flex items-center px-4 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
            <i data-lucide="arrow-left" class="w-4 h-4 mr-2"></i>
            Back to Incidents
        </a>
        
        <a href="{{ route('dashboard.domains') }}" 
           class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700">
            <i data-lucide="globe" class="w-4 h-4 mr-2"></i>
            View Domain
        </a>
    </div>
</div>
@endsection
