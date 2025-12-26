@extends('layouts.app')

@section('page-title', 'Scheduled Scans')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Scheduled Scans</h1>
            <p class="text-gray-600 mt-1">Manage automated scanning schedules for your domains</p>
        </div>
        <a href="{{ route('schedules.create') }}" 
           class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
            <i data-lucide="plus" class="w-4 h-4"></i>
            <span>New Schedule</span>
        </a>
    </div>

    @if($schedules->count() > 0)
        <!-- Schedules Table -->
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-200">
                <h2 class="text-lg font-semibold text-gray-900">Active Schedules ({{ $schedules->count() }})</h2>
            </div>
            
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Scan Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Frequency</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Next Run</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Run</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Report</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        @foreach($schedules as $schedule)
                            <tr class="hover:bg-gray-50">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex items-center">
                                        <div class="flex-shrink-0">
                                            <div class="h-8 w-8 rounded-full {{ $schedule->domain->environment === 'prod' ? 'bg-blue-100' : 'bg-yellow-100' }} flex items-center justify-center">
                                                <i data-lucide="globe" class="h-4 w-4 {{ $schedule->domain->environment === 'prod' ? 'text-blue-600' : 'text-yellow-600' }}"></i>
                                            </div>
                                        </div>
                                        <div class="ml-4">
                                            <div class="text-sm font-medium text-gray-900">{{ $schedule->domain->domain }}</div>
                                            <div class="text-sm text-gray-500">{{ ucfirst($schedule->domain->environment) === 'Prod' ? 'Production' : 'Development' }}</div>
                                        </div>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium 
                                        {{ $schedule->scan_type === 'both' ? 'bg-purple-100 text-purple-800' : 
                                           ($schedule->scan_type === 'blacklist' ? 'bg-orange-100 text-orange-800' : 'bg-blue-100 text-blue-800') }}">
                                        @if($schedule->scan_type === 'dns_security')
                                            <i data-lucide="shield" class="w-3 h-3 mr-1"></i>
                                        @elseif($schedule->scan_type === 'blacklist')
                                            <i data-lucide="shield-alert" class="w-3 h-3 mr-1"></i>
                                        @else
                                            <i data-lucide="layers" class="w-3 h-3 mr-1"></i>
                                        @endif
                                        {{ $schedule->scan_type_display }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                    {{ $schedule->frequency_display }}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                    @if($schedule->next_run_at)
                                        <div class="flex flex-col">
                                            <span class="font-medium">{{ $schedule->next_run_at->format('M j, Y') }}</span>
                                            <span class="text-gray-500">{{ $schedule->next_run_at->format('g:i A') }}</span>
                                        </div>
                                    @else
                                        <span class="text-gray-400">Not scheduled</span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    @if($schedule->last_run_at)
                                        {{ $schedule->last_run_at->diffForHumans() }}
                                    @else
                                        Never
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm">
                                    @if($schedule->latestScan)
                                        <a href="{{ route('scans.show', $schedule->latestScan) }}" 
                                           class="text-blue-600 hover:text-blue-900 hover:underline flex items-center">
                                            <i data-lucide="file-text" class="w-4 h-4 mr-1"></i>
                                            View Report
                                        </a>
                                    @else
                                        <span class="text-gray-400">—</span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $schedule->status_badge_class }}">
                                        <i data-lucide="{{ $schedule->status_icon }}" class="w-3 h-3 mr-1"></i>
                                        {{ ucfirst($schedule->status) }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <div class="flex items-center justify-end space-x-2">
                                        <!-- Scan Now -->
                                        <form action="{{ route('schedules.run-now', $schedule) }}" method="POST" class="inline">
                                            @csrf
                                            <button type="submit" 
                                                    class="text-green-600 hover:text-green-900 bg-green-50 hover:bg-green-100 px-3 py-1 rounded-md border border-green-200 hover:border-green-300">
                                                <i data-lucide="scan" class="w-4 h-4 inline mr-1"></i>
                                                Scan
                                            </button>
                                        </form>
                                        
                                        <!-- Pause/Resume -->
                                        @if($schedule->status === 'active')
                                            <form action="{{ route('schedules.pause', $schedule) }}" method="POST" class="inline">
                                                @csrf
                                                <button type="submit" 
                                                        class="text-yellow-600 hover:text-yellow-900 bg-yellow-50 hover:bg-yellow-100 px-3 py-1 rounded-md border border-yellow-200 hover:border-yellow-300">
                                                    <i data-lucide="pause" class="w-4 h-4 inline mr-1"></i>
                                                    Pause
                                                </button>
                                            </form>
                                        @elseif($schedule->status === 'paused')
                                            <form action="{{ route('schedules.resume', $schedule) }}" method="POST" class="inline">
                                                @csrf
                                                <button type="submit" 
                                                        class="text-green-600 hover:text-green-900 bg-green-50 hover:bg-green-100 px-3 py-1 rounded-md border border-green-200 hover:border-green-300">
                                                    <i data-lucide="play" class="w-4 h-4 inline mr-1"></i>
                                                    Resume
                                                </button>
                                            </form>
                                        @endif
                                        
                                        <!-- Edit -->
                                        <a href="{{ route('schedules.edit', $schedule) }}" 
                                           class="text-gray-600 hover:text-gray-900 bg-gray-50 hover:bg-gray-100 px-3 py-1 rounded-md border border-gray-200 hover:border-gray-300">
                                            <i data-lucide="edit" class="w-4 h-4 inline mr-1"></i>
                                            Edit
                                        </a>
                                        
                                        <!-- Delete -->
                                        <button onclick="showDeleteModal('{{ $schedule->domain->domain }}', {{ $schedule->id }})" 
                                                class="text-red-600 hover:text-red-900 bg-red-50 hover:bg-red-100 px-3 py-1 rounded-md border border-red-200 hover:border-red-300">
                                            <i data-lucide="trash-2" class="w-4 h-4 inline mr-1"></i>
                                            Delete
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Quick Stats -->
        <div class="grid grid-cols-1 md:grid-cols-4 gap-6">
            <div class="bg-white rounded-lg shadow-sm p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="calendar" class="h-8 w-8 text-blue-600"></i>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Total Schedules</p>
                        <p class="text-2xl font-semibold text-gray-900">{{ $schedules->count() }}</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-white rounded-lg shadow-sm p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="play-circle" class="h-8 w-8 text-green-600"></i>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Active</p>
                        <p class="text-2xl font-semibold text-gray-900">{{ $schedules->where('status', 'active')->count() }}</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-white rounded-lg shadow-sm p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="pause-circle" class="h-8 w-8 text-yellow-600"></i>
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Paused</p>
                        <p class="text-2xl font-semibold text-gray-900">{{ $schedules->where('status', 'paused')->count() }}</p>
                    </div>
                </div>
            </div>
            
            <div class="bg-white rounded-lg shadow-sm p-6">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                    </div>
                    <div class="ml-4">
                        <p class="text-sm font-medium text-gray-500">Next Run</p>
                        <p class="text-sm font-semibold text-gray-900">
                            @if($schedules->where('status', 'active')->where('next_run_at', '!=', null)->count() > 0)
                                {{ $schedules->where('status', 'active')->where('next_run_at', '!=', null)->sortBy('next_run_at')->first()->next_run_at->diffForHumans() }}
                            @else
                                No active schedules
                            @endif
                        </p>
                    </div>
                </div>
        </div>
    @else
        <!-- Empty State -->
        <div class="bg-white rounded-lg shadow-sm p-8 text-center">
            <div class="mx-auto h-12 w-12 text-gray-400">
                <i data-lucide="calendar" class="h-12 w-12"></i>
            </div>
            <h3 class="mt-4 text-lg font-medium text-gray-900">No scheduled scans yet</h3>
            <p class="mt-2 text-gray-500">Automate your domain monitoring by creating scheduled scans.</p>
            <div class="mt-6 space-y-3">
                <a href="{{ route('schedules.create') }}" 
                   class="inline-block bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg">
                    Create Your First Schedule
                </a>
                <p class="text-sm text-gray-500">
                    Or go back to <a href="{{ route('dashboard.domains') }}" class="text-blue-600 hover:text-blue-800">Domain Management</a> 
                    and use the "Schedule" button on any domain.
                </p>
            </div>
        </div>
    @endif
</div>

<!-- Delete Confirmation Modal -->
<div id="deleteModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <div class="px-6 py-4">
                <div class="flex items-center">
                    <div class="flex-shrink-0">
                        <i data-lucide="alert-triangle" class="h-6 w-6 text-red-600"></i>
                    </div>
                    <div class="ml-3">
                        <h3 class="text-lg font-medium text-gray-900">Delete Schedule</h3>
                        <p class="mt-2 text-sm text-gray-500">
                            Are you sure you want to delete the schedule for <strong id="deleteDomainName"></strong>? 
                            This action cannot be undone.
                        </p>
                    </div>
                </div>
            </div>
            <div class="px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
                <button onclick="hideDeleteModal()" 
                        class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md">
                    Cancel
                </button>
                <form id="deleteForm" method="POST" class="inline">
                    @csrf
                    @method('DELETE')
                    <button type="submit" 
                            class="px-4 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-md">
                        Delete Schedule
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
function showDeleteModal(domainName, scheduleId) {
    document.getElementById('deleteDomainName').textContent = domainName;
    document.getElementById('deleteForm').action = `{{ url('/dashboard/schedules') }}/${scheduleId}`;
    document.getElementById('deleteModal').classList.remove('hidden');
}

function hideDeleteModal() {
    document.getElementById('deleteModal').classList.add('hidden');
}
</script>
@endsection