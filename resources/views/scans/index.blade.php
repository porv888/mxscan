@extends('layouts.app')

@section('title', 'Scan History')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Security Changes</h1>
            <p class="text-gray-600 mt-1">Track what changed between scans</p>
        </div>
        <a href="{{ route('dashboard.domains') }}" 
           class="inline-flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            <i data-lucide="scan" class="w-4 h-4 mr-2"></i>
            Scan
        </a>
    </div>

    <!-- Quick Filters -->
    <div class="flex flex-wrap gap-2">
        <a href="{{ route('dashboard.scans') }}" 
           class="inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors
               {{ !($filter ?? null) ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' }}">
            All Scans
            <span class="ml-1.5 px-1.5 py-0.5 rounded-full text-xs {{ !($filter ?? null) ? 'bg-blue-200' : 'bg-gray-200' }}">{{ $totalCount ?? 0 }}</span>
        </a>
        <a href="{{ route('dashboard.scans', ['filter' => 'week']) }}" 
           class="inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors
               {{ ($filter ?? null) === 'week' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' }}">
            Last 7 Days
            <span class="ml-1.5 px-1.5 py-0.5 rounded-full text-xs {{ ($filter ?? null) === 'week' ? 'bg-blue-200' : 'bg-gray-200' }}">{{ $weekCount ?? 0 }}</span>
        </a>
        @if(($failedCount ?? 0) > 0)
        <a href="{{ route('dashboard.scans', ['filter' => 'failed']) }}" 
           class="inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors
               {{ ($filter ?? null) === 'failed' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' }}">
            Failed
            <span class="ml-1.5 px-1.5 py-0.5 rounded-full text-xs {{ ($filter ?? null) === 'failed' ? 'bg-red-200' : 'bg-gray-200' }}">{{ $failedCount ?? 0 }}</span>
        </a>
        @endif
        <a href="{{ route('dashboard.scans', ['filter' => 'dropped']) }}" 
           class="inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium transition-colors
               {{ ($filter ?? null) === 'dropped' ? 'bg-amber-100 text-amber-800' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' }}">
            <i data-lucide="trending-down" class="w-3 h-3 mr-1"></i>
            Score Dropped
        </a>
    </div>

    <!-- Scans List -->
    <div class="bg-white rounded-lg shadow">
        @if($scans->count() > 0)
            <div class="overflow-hidden">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Domain
                            </th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Change
                            </th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                Score
                            </th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                When
                            </th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                                
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        @foreach($scans as $scan)
                            @php
                                // Determine row emphasis based on change
                                $hasRegression = $scan->score_delta !== null && $scan->score_delta < 0;
                                $hasImprovement = $scan->score_delta !== null && $scan->score_delta > 0;
                                $isNoChange = $scan->score_delta === 0 || $scan->score_delta === null;
                                $rowClass = $hasRegression ? 'bg-red-50 hover:bg-red-100' : ($hasImprovement ? 'hover:bg-green-50' : 'hover:bg-gray-50 opacity-75');
                            @endphp
                            <tr class="{{ $rowClass }} transition-colors">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex items-center gap-2">
                                        @if($hasRegression)
                                            <div class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                                        @elseif($hasImprovement)
                                            <div class="w-2 h-2 rounded-full bg-green-500"></div>
                                        @endif
                                        <span class="text-sm font-medium text-gray-900">{{ $scan->domain->domain }}</span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    {{-- Show what changed, not just status --}}
                                    @if($hasRegression)
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                            <i data-lucide="trending-down" class="w-3 h-3 mr-1"></i>
                                            Score dropped
                                        </span>
                                    @elseif($hasImprovement)
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            <i data-lucide="trending-up" class="w-3 h-3 mr-1"></i>
                                            Improved
                                        </span>
                                    @elseif($scan->status === 'failed')
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                            <i data-lucide="x" class="w-3 h-3 mr-1"></i>
                                            Failed
                                        </span>
                                    @elseif($scan->status === 'running')
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                            <i data-lucide="loader" class="w-3 h-3 mr-1 animate-spin"></i>
                                            Running
                                        </span>
                                    @else
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600">
                                            <i data-lucide="minus" class="w-3 h-3 mr-1"></i>
                                            No change
                                        </span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    @if($scan->score !== null)
                                        <div class="flex items-center gap-2">
                                            <span class="text-sm font-medium 
                                                @if($scan->score >= 80) text-green-600
                                                @elseif($scan->score >= 60) text-yellow-600
                                                @else text-red-600
                                                @endif">
                                                {{ $scan->score }}%
                                            </span>
                                            @if($scan->score_delta !== null && $scan->score_delta != 0)
                                                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium
                                                    {{ $scan->score_delta > 0 ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700' }}">
                                                    @if($scan->score_delta > 0)
                                                        +{{ $scan->score_delta }}
                                                    @else
                                                        {{ $scan->score_delta }}
                                                    @endif
                                                </span>
                                            @endif
                                        </div>
                                    @else
                                        <span class="text-gray-400">--</span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {{ $scan->created_at->diffForHumans() }}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                    @if($hasRegression)
                                        <a href="{{ route('scans.show', $scan->id) }}" 
                                           class="inline-flex items-center px-2 py-1 bg-red-600 hover:bg-red-700 text-white text-xs font-medium rounded transition-colors">
                                            See what changed
                                        </a>
                                    @else
                                        <a href="{{ route('scans.show', $scan->id) }}" 
                                           class="text-blue-600 hover:text-blue-900 text-sm">
                                            View
                                        </a>
                                    @endif
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
        @else
            <!-- Empty State -->
            <div class="text-center py-12">
                <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <i data-lucide="search" class="w-8 h-8 text-gray-400"></i>
                </div>
                <h3 class="text-lg font-medium text-gray-900 mb-2">No scans yet</h3>
                <p class="text-gray-600 mb-6">Start your first domain security scan to see results here.</p>
                <a href="{{ route('dashboard.domains') }}" 
                   class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700">
                    <i data-lucide="plus" class="w-4 h-4 mr-2"></i>
                    Add Domain & Scan
                </a>
            </div>
        @endif
    </div>
</div>
@endsection
