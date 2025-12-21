@extends('layouts.app')

@section('page-title', 'SPF Optimizer - ' . $domainModel->domain)

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <nav class="flex items-center space-x-2 text-sm text-gray-500 mb-2">
                <a href="{{ route('dashboard.domains') }}" class="hover:text-gray-700">Domains</a>
                <i data-lucide="chevron-right" class="w-4 h-4"></i>
                <a href="{{ route('domains.hub', $domainModel->domain) }}" class="hover:text-gray-700">{{ $domainModel->domain }}</a>
                <i data-lucide="chevron-right" class="w-4 h-4"></i>
                <span class="text-gray-900">SPF Optimizer</span>
            </nav>
            <h1 class="text-2xl font-bold text-gray-900">SPF Optimizer</h1>
            <p class="text-gray-600 mt-1">Analyze and optimize SPF records for {{ $domainModel->domain }}</p>
        </div>
        <div class="flex items-center space-x-4">
            <form method="POST" action="{{ route('spf.run', $domainModel->domain) }}">
                @csrf
                <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
                    <i data-lucide="refresh-cw" class="w-4 h-4"></i>
                    <span>Run Check</span>
                </button>
            </form>
        </div>
    </div>

    <!-- Flash Messages -->
    @if(session('success'))
        <div class="bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded-lg">
            {{ session('success') }}
        </div>
    @endif

    @if(session('info'))
        <div class="bg-blue-50 border border-blue-200 text-blue-800 px-4 py-3 rounded-lg">
            {{ session('info') }}
        </div>
    @endif

    @if($latestCheck)
        <!-- Current Status Card -->
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <div class="flex items-center justify-between">
                    <h2 class="text-lg font-semibold text-gray-900">Current SPF Status</h2>
                    <span class="text-sm text-gray-500">Last checked: {{ $latestCheck->created_at->diffForHumans() }}</span>
                </div>
            </div>
            
            <div class="p-6 space-y-6">
                <!-- Current SPF Record -->
                <div>
                    <div class="flex items-center justify-between mb-3">
                        <h3 class="text-sm font-medium text-gray-900">Current SPF Record</h3>
                        @if($latestCheck->looked_up_record)
                            <button onclick="copyToClipboard('current-spf')" class="text-xs bg-gray-100 hover:bg-gray-200 text-gray-700 px-2 py-1 rounded">
                                Copy
                            </button>
                        @endif
                    </div>
                    @if($latestCheck->looked_up_record)
                        <div class="bg-gray-50 border rounded-lg p-3">
                            <code id="current-spf" class="text-sm text-gray-800 break-all">{{ $latestCheck->looked_up_record }}</code>
                        </div>
                    @else
                        <div class="bg-red-50 border border-red-200 rounded-lg p-3">
                            <p class="text-sm text-red-800">No SPF record found</p>
                        </div>
                    @endif
                </div>

                <!-- Lookup Count Badge -->
                <div class="flex items-center space-x-4">
                    <div>
                        <span class="text-sm font-medium text-gray-700">DNS Lookups Used:</span>
                        <span class="ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                            @if($latestCheck->lookup_status === 'safe') bg-green-100 text-green-800
                            @elseif($latestCheck->lookup_status === 'warning') bg-yellow-100 text-yellow-800
                            @else bg-red-100 text-red-800 @endif">
                            {{ $latestCheck->lookup_count }}/10
                        </span>
                    </div>
                </div>

                <!-- Warnings -->
                @if(!empty($latestCheck->warnings))
                    <div>
                        <h3 class="text-sm font-medium text-gray-900 mb-2">Warnings</h3>
                        <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                            <ul class="text-sm text-yellow-800 space-y-1">
                                @foreach($latestCheck->warning_labels as $warning)
                                    <li class="flex items-start">
                                        <i data-lucide="alert-triangle" class="w-4 h-4 mt-0.5 mr-2 flex-shrink-0"></i>
                                        {{ $warning }}
                                    </li>
                                @endforeach
                            </ul>
                        </div>
                    </div>
                @endif
            </div>
        </div>

        <!-- Flattened SPF Suggestion -->
        @if($latestCheck->flattened_suggestion)
            <div class="bg-white rounded-lg shadow-sm overflow-hidden">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-semibold text-gray-900">Flattened SPF Suggestion</h2>
                </div>
                
                <div class="p-6 space-y-4">
                    <div>
                        <div class="flex items-center justify-between mb-3">
                            <h3 class="text-sm font-medium text-gray-900">Optimized SPF Record</h3>
                            <button onclick="copyToClipboard('flattened-spf')" class="text-xs bg-blue-100 hover:bg-blue-200 text-blue-700 px-2 py-1 rounded">
                                Copy
                            </button>
                        </div>
                        <div class="bg-blue-50 border border-blue-200 rounded-lg p-3">
                            <code id="flattened-spf" class="text-sm text-blue-800 break-all">{{ $latestCheck->flattened_suggestion }}</code>
                        </div>
                        <p class="text-xs text-gray-600 mt-2">
                            <i data-lucide="info" class="w-3 h-3 inline mr-1"></i>
                            Flattening reduces lookups but may require periodic refresh if sender IPs change.
                        </p>
                    </div>

                    <!-- Resolved IPs (Collapsible) -->
                    @if(!empty($latestCheck->resolved_ips))
                        <div x-data="{ open: false }">
                            <button @click="open = !open" class="flex items-center text-sm font-medium text-gray-700 hover:text-gray-900">
                                <i data-lucide="chevron-right" class="w-4 h-4 mr-1 transition-transform" :class="{ 'rotate-90': open }"></i>
                                Resolved IP Addresses ({{ count($latestCheck->resolved_ips) }})
                            </button>
                            <div x-show="open" x-transition class="mt-2 bg-gray-50 border rounded-lg p-3">
                                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                                    @foreach($latestCheck->resolved_ips as $ip)
                                        <code class="text-xs bg-white px-2 py-1 rounded border">{{ $ip }}</code>
                                    @endforeach
                                </div>
                            </div>
                        </div>
                    @endif
                </div>
            </div>
        @endif

        <!-- History -->
        @if($history->count() > 1)
            <div class="bg-white rounded-lg shadow-sm overflow-hidden">
                <div class="px-6 py-4 border-b border-gray-200">
                    <h2 class="text-lg font-semibold text-gray-900">Check History</h2>
                </div>
                
                <div class="overflow-x-auto">
                    <table class="w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Lookups</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Changed</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Warnings</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            @foreach($history as $check)
                                <tr class="hover:bg-gray-50">
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                        {{ $check->created_at->format('M j, Y H:i') }}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                            @if($check->lookup_status === 'safe') bg-green-100 text-green-800
                                            @elseif($check->lookup_status === 'warning') bg-yellow-100 text-yellow-800
                                            @else bg-red-100 text-red-800 @endif">
                                            {{ $check->lookup_count }}/10
                                        </span>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                        @if($check->changed)
                                            <span class="text-orange-600">Yes</span>
                                        @else
                                            <span class="text-gray-500">No</span>
                                        @endif
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                        @if(!empty($check->warnings))
                                            <span class="text-yellow-600">{{ count($check->warnings) }}</span>
                                        @else
                                            <span class="text-gray-500">None</span>
                                        @endif
                                    </td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
            </div>
        @endif

    @else
        <!-- No Checks Yet -->
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="p-12 text-center">
                <i data-lucide="shield-check" class="w-16 h-16 text-gray-400 mx-auto mb-4"></i>
                <h3 class="text-lg font-medium text-gray-900 mb-2">No SPF checks yet</h3>
                <p class="text-gray-600 mb-6">Run your first SPF check to analyze your domain's email authentication setup.</p>
                <form method="POST" action="{{ route('spf.run', $domainModel->domain) }}" class="inline">
                    @csrf
                    <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg flex items-center space-x-2 mx-auto">
                        <i data-lucide="play" class="w-5 h-5"></i>
                        <span>Run First Check</span>
                    </button>
                </form>
            </div>
        </div>
    @endif

    <!-- Help Footer -->
    <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <div class="flex items-start">
            <i data-lucide="info" class="w-5 h-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0"></i>
            <div class="text-sm">
                <p class="text-blue-800 font-medium mb-1">About SPF Optimization</p>
                <p class="text-blue-700">
                    SPF records have a 10 DNS lookup limit. Our optimizer flattens include mechanisms into IP addresses to reduce lookups.
                    <a href="#" class="underline hover:no-underline">Learn more about SPF best practices</a>
                </p>
            </div>
        </div>
    </div>
</div>

<script>
function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;
    
    navigator.clipboard.writeText(text).then(function() {
        // Show toast notification
        showToast('Copied to clipboard!');
    }).catch(function(err) {
        console.error('Could not copy text: ', err);
    });
}

function showToast(message) {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = 'fixed top-4 right-4 bg-green-600 text-white px-4 py-2 rounded-lg shadow-lg z-50 transition-opacity duration-300';
    toast.textContent = message;
    
    // Add to page
    document.body.appendChild(toast);
    
    // Remove after 3 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, 3000);
}
</script>
@endsection
