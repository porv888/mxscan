@extends('layouts.app')

@section('page-title', 'Create Automation')

@section('content')
<div class="max-w-2xl mx-auto space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Create Automation</h1>
            <p class="text-gray-600 mt-1">Set up a recurring scan schedule</p>
        </div>
        <a href="{{ route('automations.index') }}" 
           class="text-gray-600 hover:text-gray-900">
            <i data-lucide="x" class="w-5 h-5"></i>
        </a>
    </div>

    <!-- Form -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <form action="{{ route('automations.store') }}" method="POST" class="space-y-6">
            @csrf

            <!-- Domain Selection -->
            <div>
                <label for="domain_id" class="block text-sm font-medium text-gray-700 mb-2">
                    Domain <span class="text-red-500">*</span>
                </label>
                <select name="domain_id" id="domain_id" required
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 @error('domain_id') border-red-500 @enderror">
                    <option value="">Select a domain</option>
                    @foreach($domains as $domain)
                        <option value="{{ $domain->id }}" {{ old('domain_id') == $domain->id ? 'selected' : '' }}>
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
                    <option value="dns" {{ old('scan_type') == 'dns' ? 'selected' : '' }}>DNS Security</option>
                    <option value="complete" {{ old('scan_type', 'complete') == 'complete' ? 'selected' : '' }}>Complete (DNS + SPF + Blacklist)</option>
                    <option value="blacklist" {{ old('scan_type') == 'blacklist' ? 'selected' : '' }}>Blacklist Only</option>
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
                    <option value="daily" {{ old('frequency', 'daily') == 'daily' ? 'selected' : '' }}>Daily</option>
                    <option value="weekly" {{ old('frequency') == 'weekly' ? 'selected' : '' }}>Weekly</option>
                    <option value="monthly" {{ old('frequency') == 'monthly' ? 'selected' : '' }}>Monthly</option>
                    <option value="custom" {{ old('frequency') == 'custom' ? 'selected' : '' }}>Custom (Cron)</option>
                </select>
                @error('frequency')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
            </div>

            <!-- Cron Expression (shown when custom is selected) -->
            <div id="cron-field" style="display: none;">
                <label for="cron_expression" class="block text-sm font-medium text-gray-700 mb-2">
                    Cron Expression
                </label>
                <input type="text" name="cron_expression" id="cron_expression" value="{{ old('cron_expression') }}"
                       placeholder="0 2 * * *"
                       class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 @error('cron_expression') border-red-500 @enderror">
                @error('cron_expression')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
                <p class="mt-1 text-xs text-gray-500">
                    Example: "0 2 * * *" runs daily at 2:00 AM
                </p>
            </div>

            <!-- Info Box -->
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div class="flex items-start">
                    <i data-lucide="info" class="w-5 h-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0"></i>
                    <div class="text-sm text-blue-800">
                        <p class="font-medium mb-1">Automation Schedule</p>
                        <p>Your automation will run automatically based on the frequency you select. You can pause, resume, or delete it at any time from the Automations page.</p>
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
                    Create Automation
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

    // Initialize on page load
    if (document.getElementById('frequency').value === 'custom') {
        document.getElementById('cron-field').style.display = 'block';
    }
</script>
@endsection
