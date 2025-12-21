@extends('layouts.app')

@section('page-title', 'Delivery Monitoring')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Delivery Monitoring</h1>
            <p class="text-gray-600 mt-1">Monitor email delivery and authentication ({{ $used }} / {{ $limit }} used)</p>
        </div>
        <div class="flex items-center space-x-4">
            @if($used >= $limit)
                <div class="text-xs text-red-600">
                    You've reached your plan limit. <a class="underline hover:no-underline" href="{{ route('pricing') }}">Upgrade</a> to create more.
                </div>
            @endif
            <a href="{{ route('delivery-monitoring.create') }}" 
               class="{{ $used >= $limit ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700' }} text-white px-4 py-2 rounded-lg flex items-center space-x-2 {{ $used >= $limit ? 'pointer-events-none' : '' }}">
                <i data-lucide="plus" class="w-4 h-4"></i>
                <span>New Monitor</span>
            </a>
        </div>
    </div>

    @if($monitors->count() > 0)
        <!-- Monitors Table -->
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-semibold text-gray-900">Your Monitors ({{ $monitors->total() }})</h2>
            </div>
            
            <div class="overflow-x-auto">
                <table class="w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Label</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden md:table-cell">Test Address</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden lg:table-cell">Domain</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider hidden xl:table-cell">Last Check</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Incidents (7d)</th>
                            <th class="px-3 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-3 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        @foreach($monitors as $monitor)
                            <tr class="hover:bg-gray-50">
                                <td class="px-3 py-4">
                                    <div class="flex items-center">
                                        <div class="flex-shrink-0">
                                            <div class="h-6 w-6 rounded-full bg-purple-100 flex items-center justify-center">
                                                <i data-lucide="mail" class="h-3 w-3 text-purple-600"></i>
                                            </div>
                                        </div>
                                        <div class="ml-2">
                                            <div class="text-sm font-medium text-gray-900">{{ $monitor->label }}</div>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-3 py-4 hidden md:table-cell">
                                    <div class="flex items-center space-x-2">
                                        <code class="text-xs bg-gray-100 px-2 py-1 rounded">{{ $monitor->inbox_address }}</code>
                                        <button onclick="copyToClipboard('{{ $monitor->inbox_address }}')" 
                                                class="text-gray-400 hover:text-gray-600">
                                            <i data-lucide="copy" class="w-4 h-4"></i>
                                        </button>
                                    </div>
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap hidden lg:table-cell">
                                    @if($monitor->domain)
                                        <span class="text-sm text-gray-900">{{ $monitor->domain->domain }}</span>
                                    @else
                                        <span class="text-xs text-gray-400">—</span>
                                    @endif
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap hidden xl:table-cell">
                                    @if($monitor->last_check_at)
                                        <span class="text-xs text-gray-600">{{ $monitor->last_check_at->diffForHumans() }}</span>
                                    @else
                                        <span class="text-xs text-gray-400">Never</span>
                                    @endif
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap">
                                    @php $incidents = $monitor->incidents_last_7 ?? 0; @endphp
                                    @if($incidents === 0)
                                        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            <i data-lucide="check-circle" class="w-3 h-3 mr-1"></i>
                                            All clear
                                        </span>
                                    @else
                                        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                            <i data-lucide="alert-circle" class="w-3 h-3 mr-1"></i>
                                            {{ $incidents }} incident{{ $incidents > 1 ? 's' : '' }}
                                        </span>
                                    @endif
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap">
                                    @if($monitor->status === 'active')
                                        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                            Active
                                        </span>
                                    @else
                                        <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                                            Paused
                                        </span>
                                    @endif
                                </td>
                                <td class="px-3 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <div class="flex items-center justify-end space-x-2">
                                        <a href="{{ route('delivery-monitoring.show', $monitor) }}" 
                                           class="text-blue-600 hover:text-blue-900">
                                            <i data-lucide="eye" class="w-4 h-4"></i>
                                        </a>
                                        @if($monitor->status === 'active')
                                            <form method="POST" action="{{ route('delivery-monitoring.pause', $monitor) }}" class="inline">
                                                @csrf
                                                <button type="submit" class="text-yellow-600 hover:text-yellow-900" title="Pause">
                                                    <i data-lucide="pause-circle" class="w-4 h-4"></i>
                                                </button>
                                            </form>
                                        @else
                                            <form method="POST" action="{{ route('delivery-monitoring.resume', $monitor) }}" class="inline">
                                                @csrf
                                                <button type="submit" class="text-green-600 hover:text-green-900" title="Resume">
                                                    <i data-lucide="play-circle" class="w-4 h-4"></i>
                                                </button>
                                            </form>
                                        @endif
                                        <form method="POST" action="{{ route('delivery-monitoring.destroy', $monitor) }}" 
                                              class="inline" 
                                              onsubmit="return confirm('Are you sure you want to delete this monitor?');">
                                            @csrf
                                            @method('DELETE')
                                            <button type="submit" class="text-red-600 hover:text-red-900" title="Delete">
                                                <i data-lucide="trash-2" class="w-4 h-4"></i>
                                            </button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            @if($monitors->hasPages())
                <div class="px-6 py-4 border-t border-gray-200">
                    {{ $monitors->links() }}
                </div>
            @endif
        </div>
    @else
        <!-- Empty State -->
        <div class="bg-white rounded-lg shadow-sm p-12 text-center">
            <div class="mx-auto h-24 w-24 text-gray-400 mb-4">
                <i data-lucide="mail" class="w-full h-full"></i>
            </div>
            <h3 class="text-lg font-medium text-gray-900 mb-2">No monitors yet</h3>
            <p class="text-gray-600 mb-6 max-w-md mx-auto">
                Create your first delivery monitor to test email delivery, authentication (SPF/DKIM/DMARC), and time-to-inbox.
            </p>
            <a href="{{ route('delivery-monitoring.create') }}" 
               class="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg">
                <i data-lucide="plus" class="w-4 h-4 mr-2"></i>
                Create Monitor
            </a>
        </div>
    @endif
</div>

<script>
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show success feedback
        alert('Copied to clipboard!');
    });
}
</script>
@endsection
