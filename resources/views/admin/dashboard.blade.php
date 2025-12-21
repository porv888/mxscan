@extends('admin.layouts.app')

@section('page-title', 'Admin Dashboard')

@section('content')
<div class="space-y-6">
    <!-- Stats Cards -->
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
        <!-- Total Users -->
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="users" class="h-6 w-6 text-gray-400"></i>
                    </div>
                    <div class="ml-5 w-0 flex-1">
                        <dl>
                            <dt class="text-sm font-medium text-gray-500 truncate">Total Users</dt>
                            <dd class="text-lg font-medium text-gray-900">{{ $totalUsers ?? 0 }}</dd>
                        </dl>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-5 py-3">
                <div class="text-sm">
                    <a href="{{ route('admin.users.index') }}" class="font-medium text-red-700 hover:text-red-900">
                        View all users
                    </a>
                </div>
            </div>
        </div>

        <!-- Active Subscriptions -->
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="repeat" class="h-6 w-6 text-gray-400"></i>
                    </div>
                    <div class="ml-5 w-0 flex-1">
                        <dl>
                            <dt class="text-sm font-medium text-gray-500 truncate">Active Subscriptions</dt>
                            <dd class="text-lg font-medium text-gray-900">{{ $activeSubscriptions ?? 0 }}</dd>
                        </dl>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-5 py-3">
                <div class="text-sm">
                    <a href="{{ route('admin.subscriptions.index') }}" class="font-medium text-red-700 hover:text-red-900">
                        View subscriptions
                    </a>
                </div>
            </div>
        </div>

        <!-- Monthly Revenue -->
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="euro" class="h-6 w-6 text-gray-400"></i>
                    </div>
                    <div class="ml-5 w-0 flex-1">
                        <dl>
                            <dt class="text-sm font-medium text-gray-500 truncate">Monthly Revenue</dt>
                            <dd class="text-lg font-medium text-gray-900">€{{ number_format($monthlyRevenue ?? 0, 2) }}</dd>
                        </dl>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-5 py-3">
                <div class="text-sm">
                    <a href="{{ route('admin.invoices.index') }}" class="font-medium text-red-700 hover:text-red-900">
                        View invoices
                    </a>
                </div>
            </div>
        </div>

        <!-- Total Scans -->
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="search" class="h-6 w-6 text-gray-400"></i>
                    </div>
                    <div class="ml-5 w-0 flex-1">
                        <dl>
                            <dt class="text-sm font-medium text-gray-500 truncate">Total Scans</dt>
                            <dd class="text-lg font-medium text-gray-900">{{ $totalScans ?? 0 }}</dd>
                        </dl>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-5 py-3">
                <div class="text-sm">
                    <a href="{{ route('admin.scans.index') }}" class="font-medium text-red-700 hover:text-red-900">
                        View all scans
                    </a>
                </div>
            </div>
        </div>

        <!-- Blacklist Status -->
        <div class="bg-white overflow-hidden shadow rounded-lg">
            <div class="p-5">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="shield-alert" class="h-6 w-6 {{ $currentlyBlacklisted > 0 ? 'text-red-400' : 'text-green-400' }}"></i>
                    </div>
                    <div class="ml-5 w-0 flex-1">
                        <dl>
                            <dt class="text-sm font-medium text-gray-500 truncate">Blacklisted IPs</dt>
                            <dd class="text-lg font-medium {{ $currentlyBlacklisted > 0 ? 'text-red-900' : 'text-green-900' }}">
                                {{ $currentlyBlacklisted ?? 0 }}
                            </dd>
                        </dl>
                    </div>
                </div>
            </div>
            <div class="bg-gray-50 px-5 py-3">
                <div class="text-sm">
                    <span class="font-medium text-gray-700">
                        {{ $totalBlacklistChecks ?? 0 }} total checks
                    </span>
                </div>
            </div>
        </div>
    </div>

    <!-- Recent Activity Section -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Recent User Registrations -->
        <div class="bg-white shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
                <h3 class="text-lg leading-6 font-medium text-gray-900 mb-4">Recent User Registrations</h3>
                <div class="flow-root">
                    <ul role="list" class="-mb-8">
                        @forelse($recentUsers ?? [] as $index => $user)
                        <li>
                            <div class="relative pb-8">
                                @if(!$loop->last)
                                <span class="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-200" aria-hidden="true"></span>
                                @endif
                                <div class="relative flex space-x-3">
                                    <div>
                                        <span class="h-8 w-8 rounded-full bg-green-500 flex items-center justify-center ring-8 ring-white">
                                            <i data-lucide="user-plus" class="h-4 w-4 text-white"></i>
                                        </span>
                                    </div>
                                    <div class="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                                        <div>
                                            <p class="text-sm text-gray-500">
                                                <span class="font-medium text-gray-900">{{ $user->name }}</span> registered
                                            </p>
                                            <p class="text-xs text-gray-400">{{ $user->email }}</p>
                                        </div>
                                        <div class="text-right text-sm whitespace-nowrap text-gray-500">
                                            <time datetime="{{ $user->created_at }}">{{ $user->created_at->diffForHumans() }}</time>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </li>
                        @empty
                        <li class="text-center py-4 text-gray-500">No recent registrations</li>
                        @endforelse
                    </ul>
                </div>
            </div>
        </div>

        <!-- Recent Scans -->
        <div class="bg-white shadow rounded-lg">
            <div class="px-4 py-5 sm:p-6">
                <h3 class="text-lg leading-6 font-medium text-gray-900 mb-4">Recent Scans</h3>
                <div class="flow-root">
                    <ul role="list" class="-mb-8">
                        @forelse($recentScans ?? [] as $scan)
                        <li>
                            <div class="relative pb-8">
                                @if(!$loop->last)
                                <span class="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-200" aria-hidden="true"></span>
                                @endif
                                <div class="relative flex space-x-3">
                                    <div>
                                        <span class="h-8 w-8 rounded-full {{ $scan->status === 'finished' ? 'bg-green-500' : ($scan->status === 'failed' ? 'bg-red-500' : 'bg-yellow-500') }} flex items-center justify-center ring-8 ring-white">
                                            @if($scan->status === 'finished')
                                                <i data-lucide="check" class="h-4 w-4 text-white"></i>
                                            @elseif($scan->status === 'failed')
                                                <i data-lucide="x" class="h-4 w-4 text-white"></i>
                                            @else
                                                <i data-lucide="clock" class="h-4 w-4 text-white"></i>
                                            @endif
                                        </span>
                                    </div>
                                    <div class="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                                        <div>
                                            <div class="flex items-center space-x-2">
                                                <p class="text-sm text-gray-500">
                                                    Scan for <span class="font-medium text-gray-900">{{ $scan->domain->domain ?? 'Unknown' }}</span>
                                                </p>
                                                @if($scan->blacklistResults && $scan->blacklistResults->count() > 0)
                                                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-orange-100 text-orange-800">
                                                        <i data-lucide="shield-check" class="w-3 h-3 mr-1"></i>
                                                        Blacklist
                                                    </span>
                                                @endif
                                            </div>
                                            <p class="text-xs text-gray-400">
                                                by {{ $scan->user->name ?? 'Unknown' }}
                                                @if($scan->status === 'finished' && $scan->score)
                                                    • Score: {{ $scan->score }}/100
                                                @endif
                                                @if($scan->blacklistResults && $scan->blacklistResults->where('status', 'listed')->count() > 0)
                                                    • <span class="text-red-600">{{ $scan->blacklistResults->where('status', 'listed')->count() }} blacklisted</span>
                                                @endif
                                            </p>
                                        </div>
                                        <div class="text-right text-sm whitespace-nowrap text-gray-500">
                                            <time datetime="{{ $scan->created_at }}">{{ $scan->created_at->diffForHumans() }}</time>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </li>
                        @empty
                        <li class="text-center py-4 text-gray-500">No recent scans</li>
                        @endforelse
                    </ul>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Actions -->
    <div class="bg-white shadow rounded-lg">
        <div class="px-4 py-5 sm:p-6">
            <h3 class="text-lg leading-6 font-medium text-gray-900 mb-4">Quick Actions</h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <a href="{{ route('admin.users.create') }}" class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    <i data-lucide="user-plus" class="mr-2 h-4 w-4"></i>
                    Add User
                </a>
                <a href="{{ route('admin.plans.create') }}" class="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    <i data-lucide="plus" class="mr-2 h-4 w-4"></i>
                    Create Plan
                </a>
                <a href="{{ route('admin.settings.index') }}" class="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    <i data-lucide="settings" class="mr-2 h-4 w-4"></i>
                    Settings
                </a>
                <a href="{{ route('admin.audit.index') }}" class="inline-flex items-center px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500">
                    <i data-lucide="file-text" class="mr-2 h-4 w-4"></i>
                    View Logs
                </a>
            </div>
        </div>
    </div>
</div>
@endsection