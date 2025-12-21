@extends('layouts.app')

@section('page-title', 'Create Delivery Monitor')

@section('content')
<div class="max-w-2xl mx-auto space-y-6">
    <!-- Header -->
    <div>
        <h1 class="text-2xl font-bold text-gray-900">Create Delivery Monitor</h1>
        <p class="text-gray-600 mt-1">Set up a new email delivery test monitor</p>
    </div>

    <!-- Form Card -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <form method="POST" action="{{ route('delivery-monitoring.store') }}">
            @csrf

            <!-- Label -->
            <div class="mb-6">
                <label for="label" class="block text-sm font-medium text-gray-700 mb-2">
                    Monitor Label <span class="text-red-500">*</span>
                </label>
                <input type="text" 
                       name="label" 
                       id="label" 
                       value="{{ old('label') }}"
                       class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 @error('label') border-red-500 @enderror"
                       placeholder="e.g., Production Mail Server"
                       required>
                @error('label')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
                <p class="mt-1 text-xs text-gray-500">A descriptive name for this monitor</p>
            </div>

            <!-- Domain (Optional) -->
            <div class="mb-6">
                <label for="domain_id" class="block text-sm font-medium text-gray-700 mb-2">
                    Associated Domain (Optional)
                </label>
                <select name="domain_id" 
                        id="domain_id" 
                        class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    <option value="">None</option>
                    @foreach($domains as $domain)
                        <option value="{{ $domain->id }}" {{ old('domain_id') == $domain->id ? 'selected' : '' }}>
                            {{ $domain->domain }}
                        </option>
                    @endforeach
                </select>
                @error('domain_id')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
                <p class="mt-1 text-xs text-gray-500">Link this monitor to one of your domains for easier tracking</p>
            </div>

            <!-- Info Box -->
            <div class="mb-6 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                <div class="flex items-start">
                    <i data-lucide="info" class="w-5 h-5 text-blue-600 mr-3 mt-0.5 flex-shrink-0"></i>
                    <div class="text-sm text-blue-900">
                        <p class="font-medium mb-1">How it works:</p>
                        <ul class="list-disc list-inside space-y-1 text-blue-800">
                            <li>We'll generate a unique test email address for you</li>
                            <li>Send test emails to this address from your mail server</li>
                            <li>We'll check SPF, DKIM, DMARC authentication</li>
                            <li>We'll measure time-to-inbox (TTI)</li>
                            <li>You'll be alerted if any issues are detected</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Usage Info -->
            <div class="mb-6 p-4 bg-gray-50 border border-gray-200 rounded-lg">
                <div class="flex items-center justify-between text-sm">
                    <span class="text-gray-700">Monitor usage:</span>
                    <span class="font-medium text-gray-900">{{ $used }} / {{ $limit }} used</span>
                </div>
            </div>

            <!-- Actions -->
            <div class="flex items-center justify-end space-x-3">
                <a href="{{ route('delivery-monitoring.index') }}" 
                   class="px-4 py-2 text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-lg">
                    Cancel
                </a>
                <button type="submit" 
                        class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg flex items-center space-x-2">
                    <i data-lucide="plus" class="w-4 h-4"></i>
                    <span>Create Monitor</span>
                </button>
            </div>
        </form>
    </div>
</div>
@endsection
