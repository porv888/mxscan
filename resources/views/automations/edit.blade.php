@extends('layouts.app')

@section('page-title', 'Edit Automation')

@section('content')
<div class="max-w-2xl mx-auto space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Edit Automation</h1>
            <p class="text-gray-600 mt-1">Update your recurring scan schedule</p>
        </div>
        <a href="{{ route('automations.index') }}" 
           class="text-gray-600 hover:text-gray-900">
            <i data-lucide="x" class="w-5 h-5"></i>
        </a>
    </div>

    <!-- Form -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <form action="{{ route('automations.update', $schedule) }}" method="POST" class="space-y-6">
            @csrf
            @method('PUT')

            <!-- Domain Selection -->
            <div>
                <label for="domain_id" class="block text-sm font-medium text-gray-700 mb-2">
                    Domain <span class="text-red-500">*</span>
                </label>
                <select name="domain_id" id="domain_id" required
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 @error('domain_id') border-red-500 @enderror">
                    <option value="">Select a domain</option>
                    @foreach($domains as $domain)
                        <option value="{{ $domain->id }}" {{ old('domain_id', $schedule->domain_id) == $domain->id ? 'selected' : '' }}>
                            {{ $domain->domain }}
                        </option>
                    @endforeach
                </select>
                @error('domain_id')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
            </div>

            <!-- Scan Type -->
            <div>
                <label for="scan_type" class="block text-sm font-medium text-gray-700 mb-2">
                    Schedule Type <span class="text-red-500">*</span>
                </label>
                <select name="scan_type" id="scan_type" required
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 @error('scan_type') border-red-500 @enderror">
                    @php
                        $currentType = old('scan_type', $schedule->scan_type);
                        // Map legacy types to new types
                        $mappedType = match($currentType) {
                            'dns_security' => 'dns',
                            'both' => 'complete',
                            'blacklist' => 'blacklist',
                            default => 'dns'
                        };
                    @endphp
                    <option value="dns" {{ $mappedType == 'dns' ? 'selected' : '' }}>DNS Security</option>
                    <option value="complete" {{ $mappedType == 'complete' ? 'selected' : '' }}>Complete (DNS + SPF + Blacklist)</option>
                    <option value="blacklist" {{ $mappedType == 'blacklist' ? 'selected' : '' }}>Blacklist Only</option>
                </select>
                @error('scan_type')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
                <p class="mt-1 text-xs text-gray-500">
                    Note: Blacklist monitoring requires a Premium or Ultra plan
                </p>
            </div>

            <!-- Frequency -->
            <div>
                <label for="frequency" class="block text-sm font-medium text-gray-700 mb-2">
                    Frequency <span class="text-red-500">*</span>
                </label>
                <select name="frequency" id="frequency" required
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 @error('frequency') border-red-500 @enderror">
                    <option value="daily" {{ old('frequency', $schedule->frequency) == 'daily' ? 'selected' : '' }}>Daily</option>
                    <option value="weekly" {{ old('frequency', $schedule->frequency) == 'weekly' ? 'selected' : '' }}>Weekly</option>
                    <option value="monthly" {{ old('frequency', $schedule->frequency) == 'monthly' ? 'selected' : '' }}>Monthly</option>
                    <option value="custom" {{ old('frequency', $schedule->frequency) == 'custom' ? 'selected' : '' }}>Custom (Cron)</option>
                </select>
                @error('frequency')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
            </div>

            <!-- Cron Expression (shown when custom is selected) -->
            <div id="cron-field" style="display: {{ old('frequency', $schedule->frequency) == 'custom' ? 'block' : 'none' }};">
                <label for="cron_expression" class="block text-sm font-medium text-gray-700 mb-2">
                    Cron Expression
                </label>
                <input type="text" name="cron_expression" id="cron_expression" value="{{ old('cron_expression', $schedule->cron_expression) }}"
                       placeholder="0 2 * * *"
                       class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 @error('cron_expression') border-red-500 @enderror">
                @error('cron_expression')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
                <p class="mt-1 text-xs text-gray-500">
                    Example: "0 2 * * *" runs daily at 2:00 AM
                </p>
            </div>

            <!-- Status Info -->
            <div class="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <div class="grid grid-cols-2 gap-4 text-sm">
                    <div>
                        <span class="text-gray-600">Status:</span>
                        <span class="ml-2 font-medium {{ $schedule->status === 'active' ? 'text-green-600' : 'text-yellow-600' }}">
                            {{ ucfirst($schedule->status) }}
                        </span>
                    </div>
                    <div>
                        <span class="text-gray-600">Next Run:</span>
                        <span class="ml-2 font-medium text-gray-900">
                            {{ $schedule->next_run_at ? $schedule->next_run_at->diffForHumans() : 'Not scheduled' }}
                        </span>
                    </div>
                    <div>
                        <span class="text-gray-600">Last Run:</span>
                        <span class="ml-2 font-medium text-gray-900">
                            {{ $schedule->last_run_at ? $schedule->last_run_at->diffForHumans() : 'Never' }}
                        </span>
                    </div>
                    <div>
                        <span class="text-gray-600">Created:</span>
                        <span class="ml-2 font-medium text-gray-900">
                            {{ $schedule->created_at->diffForHumans() }}
                        </span>
                    </div>
                </div>
            </div>

            <!-- Actions -->
            <div class="flex items-center justify-end space-x-3 pt-4 border-t border-gray-200">
                <a href="{{ route('automations.index') }}" 
                   class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md">
                    Cancel
                </a>
                <button type="submit" 
                        class="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md">
                    Save Changes
                </button>
            </div>
        </form>
    </div>
</div>

<script>
    // Show/hide cron expression field based on frequency selection
    document.getElementById('frequency').addEventListener('change', function() {
        const cronField = document.getElementById('cron-field');
        if (this.value === 'custom') {
            cronField.style.display = 'block';
        } else {
            cronField.style.display = 'none';
        }
    });
</script>
@endsection
