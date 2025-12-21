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

    <!-- Welcome Message -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <h1 class="text-2xl font-bold text-gray-900">Welcome, {{ Auth::user()->name }}</h1>
        <p class="text-gray-600 mt-2">Monitor your email security across all domains from this dashboard.</p>
    </div>

    <!-- Stats Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        <!-- Total Domains -->
        <div class="bg-white rounded-lg shadow-sm p-6">
            <div class="flex items-center">
                <div class="p-3 rounded-full bg-blue-100">
                    <i data-lucide="globe" class="w-6 h-6 text-blue-600"></i>
                </div>
                <div class="ml-4">
                    <p class="text-sm font-medium text-gray-600">Total Domains</p>
                    <p class="text-2xl font-bold text-gray-900">{{ $totalDomains ?? 0 }}</p>
                </div>
            </div>
        </div>

        <!-- Last Scan Date -->
        <div class="bg-white rounded-lg shadow-sm p-6">
            <div class="flex items-center">
                <div class="p-3 rounded-full bg-green-100">
                    <i data-lucide="calendar" class="w-6 h-6 text-green-600"></i>
                </div>
                <div class="ml-4">
                    <p class="text-sm font-medium text-gray-600">Last Scan</p>
                    <p class="text-2xl font-bold text-gray-900">
                        @if($lastScanDate ?? null)
                            {{ $lastScanDate->diffForHumans() }}
                        @else
                            Never
                        @endif
                    </p>
                </div>
            </div>
        </div>

        <!-- Average Security Score -->
        <div class="bg-white rounded-lg shadow-sm p-6">
            <div class="flex items-center">
                <div class="p-3 rounded-full bg-yellow-100">
                    <i data-lucide="shield-check" class="w-6 h-6 text-yellow-600"></i>
                </div>
                <div class="ml-4">
                    <p class="text-sm font-medium text-gray-600">Avg Security Score</p>
                    <p class="text-2xl font-bold text-gray-900">
                        @if($averageScore ?? null)
                            {{ number_format($averageScore, 1) }}%
                        @else
                            --
                        @endif
                    </p>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Activity -->
    <div class="bg-white rounded-lg shadow-sm">
        <div class="px-6 py-4 border-b border-gray-200">
            <div class="flex items-center justify-between">
                <h2 class="text-lg font-semibold text-gray-900">Recent Scan Activity</h2>
                <a href="{{ route('dashboard.scans') }}" class="text-blue-600 hover:text-blue-800 text-sm font-medium">
                    View All
                </a>
            </div>
        </div>
        
        <div class="p-6">
            @if(isset($recentScans) && $recentScans->count() > 0)
                <div class="space-y-4">
                    @foreach($recentScans as $scan)
                        <div class="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                            <div class="flex items-center space-x-4">
                                <!-- Status Icon -->
                                <div class="flex-shrink-0">
                                    @if($scan->status === 'finished')
                                        <div class="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                                            <i data-lucide="check" class="w-4 h-4 text-green-600"></i>
                                        </div>
                                    @elseif($scan->status === 'running')
                                        <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                                            <i data-lucide="loader" class="w-4 h-4 text-blue-600 animate-spin"></i>
                                        </div>
                                    @elseif($scan->status === 'failed')
                                        <div class="w-8 h-8 bg-red-100 rounded-full flex items-center justify-center">
                                            <i data-lucide="x" class="w-4 h-4 text-red-600"></i>
                                        </div>
                                    @else
                                        <div class="w-8 h-8 bg-gray-100 rounded-full flex items-center justify-center">
                                            <i data-lucide="clock" class="w-4 h-4 text-gray-600"></i>
                                        </div>
                                    @endif
                                </div>
                                
                                <!-- Scan Info -->
                                <div>
                                    <p class="font-medium text-gray-900">{{ $scan->domain->domain }}</p>
                                    <p class="text-sm text-gray-600">
                                        {{ ucfirst($scan->status) }} • 
                                        {{ $scan->created_at->diffForHumans() }}
                                    </p>
                                </div>
                            </div>
                            
                            <!-- Score and Actions -->
                            <div class="flex items-center space-x-4">
                                @if($scan->score !== null)
                                    <div class="text-right">
                                        <p class="text-sm text-gray-600">Security Score</p>
                                        <p class="font-bold text-lg 
                                            @if($scan->score >= 80) text-green-600
                                            @elseif($scan->score >= 60) text-yellow-600
                                            @else text-red-600
                                            @endif">
                                            {{ $scan->score }}%
                                        </p>
                                    </div>
                                @endif
                                
                                <a href="{{ route('scans.show', $scan->id) }}" 
                                   class="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50">
                                    <i data-lucide="eye" class="w-4 h-4 mr-2"></i>
                                    View
                                </a>
                            </div>
                        </div>
                    @endforeach
                </div>
            @else
                <!-- Empty State -->
                <div class="text-center py-12">
                    <div class="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                        <i data-lucide="search" class="w-8 h-8 text-gray-400"></i>
                    </div>
                    <h3 class="text-lg font-medium text-gray-900 mb-2">No scans yet</h3>
                    <p class="text-gray-600 mb-6">Add a domain and run your first security scan to get started.</p>
                    <a href="{{ route('dashboard.domains') }}" 
                       class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700">
                        <i data-lucide="plus" class="w-4 h-4 mr-2"></i>
                        Add Domain
                    </a>
                </div>
            @endif
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <h2 class="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            <a href="{{ route('dashboard.domains') }}" 
               class="flex items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <div class="p-2 bg-blue-100 rounded-lg mr-4">
                    <i data-lucide="plus" class="w-5 h-5 text-blue-600"></i>
                </div>
                <div>
                    <p class="font-medium text-gray-900">Add Domain</p>
                    <p class="text-sm text-gray-600">Register a new domain for monitoring</p>
                </div>
            </a>
            
            <a href="{{ route('dashboard.domains') }}" 
               class="flex items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <div class="p-2 bg-green-100 rounded-lg mr-4">
                    <i data-lucide="play" class="w-5 h-5 text-green-600"></i>
                </div>
                <div>
                    <p class="font-medium text-gray-900">Run Scan</p>
                    <p class="text-sm text-gray-600">Start a new security scan</p>
                </div>
            </a>
            
            <a href="{{ route('dashboard.scans') }}" 
               class="flex items-center p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
                <div class="p-2 bg-purple-100 rounded-lg mr-4">
                    <i data-lucide="bar-chart" class="w-5 h-5 text-purple-600"></i>
                </div>
                <div>
                    <p class="font-medium text-gray-900">View Reports</p>
                    <p class="text-sm text-gray-600">Check detailed scan results</p>
                </div>
            </a>
        </div>
    </div>
</div>
@endsection
