@extends('layouts.app')

@section('page-title', 'Automations')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Automations</h1>
            <p class="text-gray-600 mt-1">Manage recurring scan schedules for your domains</p>
        </div>
        <a href="{{ route('automations.create') }}" 
           class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
            <i data-lucide="plus" class="w-4 h-4"></i>
            <span>New Automation</span>
        </a>
    </div>

    @if($schedules->count() > 0)
        <!-- Automations Table -->
        <div class="bg-white rounded-lg shadow-sm overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Domain</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Schedule Type</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Frequency</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Next Run</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Run</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                            <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        @foreach($schedules as $schedule)
                            <tr class="hover:bg-gray-50">
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <div class="flex items-center">
                                        <i data-lucide="globe" class="w-4 h-4 text-gray-400 mr-2"></i>
                                        <span class="text-sm font-medium text-gray-900">{{ $schedule->domain->domain }}</span>
                                    </div>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium
                                        {{ $schedule->scan_type === 'both' ? 'bg-purple-100 text-purple-800' : 
                                           ($schedule->scan_type === 'blacklist' ? 'bg-red-100 text-red-800' : 'bg-blue-100 text-blue-800') }}">
                                        {{ $schedule->scan_type_display }}
                                    </span>
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                    {{ $schedule->frequency_display }}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    @if($schedule->next_run_at)
                                        <span title="{{ $schedule->next_run_at->format('Y-m-d H:i:s') }}">
                                            {{ $schedule->next_run_at->diffForHumans() }}
                                        </span>
                                    @else
                                        —
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    @if($schedule->last_run_at)
                                        <div class="flex items-center space-x-2">
                                            <span title="{{ $schedule->last_run_at->format('Y-m-d H:i:s') }}">
                                                {{ $schedule->last_run_at->diffForHumans() }}
                                            </span>
                                            @if($schedule->last_run_status)
                                                <span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium {{ $schedule->last_run_status_badge_class }}">
                                                    {{ ucfirst($schedule->last_run_status) }}
                                                </span>
                                            @endif
                                        </div>
                                    @else
                                        Never
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    @if($schedule->is_running)
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                            <svg class="animate-spin h-3 w-3 mr-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                                                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                            </svg>
                                            Running
                                        </span>
                                    @else
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium {{ $schedule->status_badge_class }}">
                                            <i data-lucide="{{ $schedule->status_icon }}" class="w-3 h-3 mr-1"></i>
                                            {{ ucfirst($schedule->status) }}
                                        </span>
                                    @endif
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <div class="flex items-center justify-end space-x-2">
                                        <!-- Run Now -->
                                        <form action="{{ route('automations.run-now', $schedule) }}" method="POST" class="inline">
                                            @csrf
                                            <button type="submit" 
                                                    class="text-blue-600 hover:text-blue-900 disabled:opacity-50 disabled:cursor-not-allowed"
                                                    title="Run now"
                                                    @if($schedule->is_running) disabled @endif>
                                                <i data-lucide="play" class="w-4 h-4"></i>
                                            </button>
                                        </form>

                                        <!-- Pause/Resume -->
                                        @if($schedule->status === 'active')
                                            <form action="{{ route('automations.pause', $schedule) }}" method="POST" class="inline">
                                                @csrf
                                                <button type="submit" 
                                                        class="text-yellow-600 hover:text-yellow-900"
                                                        title="Pause">
                                                    <i data-lucide="pause" class="w-4 h-4"></i>
                                                </button>
                                            </form>
                                        @else
                                            <form action="{{ route('automations.resume', $schedule) }}" method="POST" class="inline">
                                                @csrf
                                                <button type="submit" 
                                                        class="text-green-600 hover:text-green-900"
                                                        title="Resume">
                                                    <i data-lucide="play-circle" class="w-4 h-4"></i>
                                                </button>
                                            </form>
                                        @endif

                                        <!-- Edit -->
                                        <a href="{{ route('automations.edit', $schedule) }}" 
                                           class="text-gray-600 hover:text-gray-900"
                                           title="Edit">
                                            <i data-lucide="edit" class="w-4 h-4"></i>
                                        </a>

                                        <!-- Delete -->
                                        <form action="{{ route('automations.destroy', $schedule) }}" 
                                              method="POST" 
                                              class="inline"
                                              onsubmit="return confirm('Are you sure you want to delete this automation?');">
                                            @csrf
                                            @method('DELETE')
                                            <button type="submit" 
                                                    class="text-red-600 hover:text-red-900"
                                                    title="Delete">
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
        </div>
    @else
        <!-- Empty State -->
        <div class="bg-white rounded-lg shadow-sm p-8 text-center">
            <div class="mx-auto h-12 w-12 text-gray-400">
                <i data-lucide="calendar" class="h-12 w-12"></i>
            </div>
            <h3 class="mt-4 text-lg font-medium text-gray-900">No automations yet</h3>
            <p class="mt-2 text-gray-500">Set up recurring scans to automate your email security monitoring.</p>
            <a href="{{ route('automations.create') }}" 
               class="mt-4 inline-block bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg">
                Create Your First Automation
            </a>
        </div>
    @endif
</div>
@endsection
