@extends('layouts.app')

@section('page-title', 'Create Schedule')

@section('content')
<div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Create Schedule</h1>
            <p class="text-gray-600 mt-1">Set up automated scanning for your domains</p>
        </div>
        <a href="{{ route('schedules.index') }}" 
           class="bg-gray-100 hover:bg-gray-200 text-gray-700 px-4 py-2 rounded-lg flex items-center space-x-2">
            <i data-lucide="arrow-left" class="w-4 h-4"></i>
            <span>Back to Schedules</span>
        </a>
    </div>

    <!-- Create Form -->
    <div class="bg-white rounded-lg shadow p-6">
        <form action="{{ route('schedules.store') }}" method="POST" class="space-y-6">
            @csrf

            <!-- Domain Selection -->
            <div>
                <label for="domain_id" class="block text-sm font-medium text-gray-700 mb-2">
                    Domain
                </label>
                <select name="domain_id" id="domain_id" required
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    <option value="">Select a domain</option>
                    @foreach($domains as $domain)
                        <option value="{{ $domain->id }}" {{ old('domain_id') == $domain->id ? 'selected' : '' }}>
                            {{ $domain->domain }} ({{ ucfirst($domain->environment) }})
                        </option>
                    @endforeach
                </select>
                @error('domain_id')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
            </div>

            <!-- Scan Type -->
            <div>
                <label class="block text-sm font-medium text-gray-700 mb-3">Scan Type</label>
                <div class="space-y-3">
                    <div class="flex items-start">
                        <div class="flex items-center h-5">
                            <input id="dns_security" name="scan_type" value="dns_security" type="radio" 
                                   {{ old('scan_type', 'dns_security') == 'dns_security' ? 'checked' : '' }}
                                   class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300">
                        </div>
                        <div class="ml-3 text-sm">
                            <label for="dns_security" class="font-medium text-gray-700">DNS Security Only</label>
                            <p class="text-gray-500">Check MX, SPF, DMARC, TLS-RPT, and MTA-STS records</p>
                        </div>
                    </div>
                    
                    <div class="flex items-start">
                        <div class="flex items-center h-5">
                            <input id="blacklist" name="scan_type" value="blacklist" type="radio" 
                                   {{ old('scan_type') == 'blacklist' ? 'checked' : '' }}
                                   class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300">
                        </div>
                        <div class="ml-3 text-sm">
                            <label for="blacklist" class="font-medium text-gray-700">Blacklist Monitoring Only</label>
                            <p class="text-gray-500">Check domain IPs against spam blacklists</p>
                        </div>
                    </div>
                    
                    <div class="flex items-start">
                        <div class="flex items-center h-5">
                            <input id="both" name="scan_type" value="both" type="radio" 
                                   {{ old('scan_type') == 'both' ? 'checked' : '' }}
                                   class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300">
                        </div>
                        <div class="ml-3 text-sm">
                            <label for="both" class="font-medium text-gray-700">Complete Scan</label>
                            <p class="text-gray-500">DNS security + blacklist monitoring (recommended)</p>
                        </div>
                    </div>
                </div>
                @error('scan_type')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
            </div>

            <!-- Frequency -->
            <div>
                <label for="frequency" class="block text-sm font-medium text-gray-700 mb-2">
                    Frequency
                </label>
                <select name="frequency" id="frequency" required
                        class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                    <option value="daily" {{ old('frequency') == 'daily' ? 'selected' : '' }}>Daily (2:00 AM)</option>
                    <option value="weekly" {{ old('frequency', 'weekly') == 'weekly' ? 'selected' : '' }}>Weekly (Monday 2:00 AM)</option>
                    <option value="monthly" {{ old('frequency') == 'monthly' ? 'selected' : '' }}>Monthly (1st of month 2:00 AM)</option>
                </select>
                @error('frequency')
                    <p class="mt-1 text-sm text-red-600">{{ $message }}</p>
                @enderror
            </div>

            <!-- Pro Plan Notice -->
            <div class="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <div class="flex items-start">
                    <i data-lucide="info" class="w-5 h-5 text-blue-600 mt-0.5 mr-3 flex-shrink-0"></i>
                    <div class="text-sm">
                        <p class="text-blue-800 font-medium">Scheduling Information</p>
                        <ul class="text-blue-700 mt-1 space-y-1">
                            <li>• Scheduled scans run automatically at the specified times</li>
                            <li>• You can pause or modify schedules at any time</li>
                            <li>• Blacklist monitoring may require a Pro plan subscription</li>
                        </ul>
                    </div>
                </div>
            </div>

            <!-- Submit Buttons -->
            <div class="flex justify-end space-x-3 pt-6 border-t">
                <a href="{{ route('schedules.index') }}" 
                   class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md">
                    Cancel
                </a>
                <button type="submit" 
                        class="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md">
                    Create Schedule
                </button>
            </div>
        </form>
    </div>
</div>
@endsection