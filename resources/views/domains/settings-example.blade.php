@extends('layouts.app')

@section('page-title', 'Domain Settings - ' . $domain->domain)

@section('content')
<div class="max-w-4xl mx-auto space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">{{ $domain->domain }}</h1>
            <p class="text-gray-600 mt-1">Configure monitoring services and scan schedule</p>
        </div>
        <a href="{{ route('domains') }}" class="text-gray-600 hover:text-gray-900">
            <i data-lucide="x" class="w-5 h-5"></i>
        </a>
    </div>

    <!-- Service Selection Card -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <h2 class="text-lg font-semibold text-gray-900 mb-4">Monitoring Services</h2>
        <p class="text-sm text-gray-600 mb-6">Select which services to monitor for this domain. Changes take effect immediately.</p>

        <form method="POST" action="{{ route('domains.settings.services', $domain) }}" class="space-y-4">
            @csrf
            
            <!-- DNS Security -->
            <label class="flex items-start p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors {{ ($enabled['dns'] ?? true) ? 'border-blue-500 bg-blue-50' : 'border-gray-200' }}">
                <input type="checkbox" name="services[]" value="dns" 
                       {{ ($enabled['dns'] ?? true) ? 'checked' : '' }}
                       class="mt-1 h-5 w-5 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                <div class="ml-4 flex-1">
                    <div class="flex items-center justify-between">
                        <span class="text-sm font-semibold text-gray-900">DNS Security</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                            Core
                        </span>
                    </div>
                    <p class="text-sm text-gray-600 mt-1">Monitor MX, SPF, DMARC, TLS-RPT, and MTA-STS records</p>
                    <div class="mt-2 flex flex-wrap gap-2">
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check" class="w-3 h-3 mr-1"></i>MX Records
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check" class="w-3 h-3 mr-1"></i>DMARC
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check" class="w-3 h-3 mr-1"></i>TLS-RPT
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check" class="w-3 h-3 mr-1"></i>MTA-STS
                        </span>
                    </div>
                </div>
            </label>

            <!-- SPF Analysis -->
            <label class="flex items-start p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors {{ ($enabled['spf'] ?? true) ? 'border-blue-500 bg-blue-50' : 'border-gray-200' }}">
                <input type="checkbox" name="services[]" value="spf" 
                       {{ ($enabled['spf'] ?? true) ? 'checked' : '' }}
                       class="mt-1 h-5 w-5 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                <div class="ml-4 flex-1">
                    <div class="flex items-center justify-between">
                        <span class="text-sm font-semibold text-gray-900">SPF Analysis</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                            Core
                        </span>
                    </div>
                    <p class="text-sm text-gray-600 mt-1">Track SPF record changes and DNS lookup counts (RFC 7208 limit: 10)</p>
                    <div class="mt-2 flex flex-wrap gap-2">
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check" class="w-3 h-3 mr-1"></i>Lookup Tracking
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check" class="w-3 h-3 mr-1"></i>Change Detection
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check" class="w-3 h-3 mr-1"></i>Flattening Suggestions
                        </span>
                    </div>
                </div>
            </label>

            <!-- Blacklist Monitoring -->
            <label class="flex items-start p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors {{ ($enabled['blacklist'] ?? true) ? 'border-blue-500 bg-blue-50' : 'border-gray-200' }}">
                <input type="checkbox" name="services[]" value="blacklist" 
                       {{ ($enabled['blacklist'] ?? true) ? 'checked' : '' }}
                       class="mt-1 h-5 w-5 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                <div class="ml-4 flex-1">
                    <div class="flex items-center justify-between">
                        <span class="text-sm font-semibold text-gray-900">Blacklist Monitoring</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                            Premium
                        </span>
                    </div>
                    <p class="text-sm text-gray-600 mt-1">Check your mail servers against 23+ RBL providers</p>
                    <div class="mt-2 flex flex-wrap gap-2">
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="shield" class="w-3 h-3 mr-1"></i>Spamhaus
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="shield" class="w-3 h-3 mr-1"></i>Barracuda
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="shield" class="w-3 h-3 mr-1"></i>SORBS
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            +20 more
                        </span>
                    </div>
                </div>
            </label>

            <!-- Delivery Monitoring -->
            <label class="flex items-start p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors {{ ($enabled['delivery'] ?? false) ? 'border-blue-500 bg-blue-50' : 'border-gray-200' }}">
                <input type="checkbox" name="services[]" value="delivery" 
                       {{ ($enabled['delivery'] ?? false) ? 'checked' : '' }}
                       class="mt-1 h-5 w-5 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                <div class="ml-4 flex-1">
                    <div class="flex items-center justify-between">
                        <span class="text-sm font-semibold text-gray-900">Delivery Monitoring</span>
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-purple-100 text-purple-800">
                            Premium
                        </span>
                    </div>
                    <p class="text-sm text-gray-600 mt-1">Track email delivery times and authentication results in real-time</p>
                    <div class="mt-2 flex flex-wrap gap-2">
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="clock" class="w-3 h-3 mr-1"></i>Time-to-Inbox
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="check-circle" class="w-3 h-3 mr-1"></i>SPF/DKIM/DMARC
                        </span>
                        <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-700">
                            <i data-lucide="mail" class="w-3 h-3 mr-1"></i>Inbox Address
                        </span>
                    </div>
                    @if($enabled['delivery'] ?? false)
                        @php
                            $monitor = $domain->deliveryMonitors()->first();
                        @endphp
                        @if($monitor)
                            <div class="mt-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                                <p class="text-xs font-medium text-blue-900 mb-1">Your monitoring address:</p>
                                <code class="text-xs text-blue-700 bg-white px-2 py-1 rounded">{{ $monitor->inbox_address }}</code>
                                <p class="text-xs text-blue-600 mt-2">Send test emails to this address to monitor delivery.</p>
                            </div>
                        @endif
                    @endif
                </div>
            </label>

            <!-- Submit Button -->
            <div class="flex justify-end pt-4 border-t">
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                    <i data-lucide="save" class="w-4 h-4 inline mr-2"></i>
                    Save Services
                </button>
            </div>
        </form>
    </div>

    <!-- Scan Schedule Card -->
    <div class="bg-white rounded-lg shadow-sm p-6">
        <h2 class="text-lg font-semibold text-gray-900 mb-4">Scan Schedule</h2>
        <p class="text-sm text-gray-600 mb-6">Configure when automatic scans should run. All times are in UTC.</p>

        <form method="POST" action="{{ route('domains.settings.cadence', $domain) }}" class="space-y-4">
            @csrf

            <!-- Schedule Options -->
            <div class="space-y-3">
                <label class="flex items-center p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors {{ $cadence === 'off' ? 'border-blue-500 bg-blue-50' : 'border-gray-200' }}">
                    <input type="radio" name="schedule_type" value="off" 
                           {{ $cadence === 'off' ? 'checked' : '' }}
                           class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300">
                    <div class="ml-3">
                        <span class="text-sm font-medium text-gray-900">Manual Only</span>
                        <p class="text-xs text-gray-600">No automatic scans. Run scans manually when needed.</p>
                    </div>
                </label>

                <label class="flex items-center p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors {{ $cadence === 'daily' ? 'border-blue-500 bg-blue-50' : 'border-gray-200' }}">
                    <input type="radio" name="schedule_type" value="daily" 
                           {{ $cadence === 'daily' ? 'checked' : '' }}
                           class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300">
                    <div class="ml-3 flex-1">
                        <div class="flex items-center justify-between">
                            <span class="text-sm font-medium text-gray-900">Daily</span>
                            <span class="inline-flex items-center px-2 py-0.5 rounded text-xs bg-green-100 text-green-800">
                                Recommended
                            </span>
                        </div>
                        <p class="text-xs text-gray-600">Run scans every day at a specified time.</p>
                    </div>
                </label>

                <label class="flex items-center p-4 border rounded-lg cursor-pointer hover:bg-gray-50 transition-colors {{ $cadence === 'weekly' ? 'border-blue-500 bg-blue-50' : 'border-gray-200' }}">
                    <input type="radio" name="schedule_type" value="weekly" 
                           {{ $cadence === 'weekly' ? 'checked' : '' }}
                           class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300">
                    <div class="ml-3">
                        <span class="text-sm font-medium text-gray-900">Weekly</span>
                        <p class="text-xs text-gray-600">Run scans once per week at a specified time.</p>
                    </div>
                </label>
            </div>

            <!-- Time Picker (shown when daily or weekly is selected) -->
            <div id="time-picker-container" class="{{ in_array($cadence, ['daily', 'weekly']) ? '' : 'hidden' }}">
                <label for="schedule_time" class="block text-sm font-medium text-gray-700 mb-2">
                    Run at (UTC):
                </label>
                <div class="flex items-center space-x-3">
                    <input type="time" id="schedule_time" name="schedule_time" 
                           value="{{ $runAt ? substr($runAt, 0, 5) : '09:00' }}"
                           class="block w-40 px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm">
                    <span class="text-sm text-gray-500">
                        <i data-lucide="info" class="w-4 h-4 inline mr-1"></i>
                        Current UTC time: <span id="current-utc-time" class="font-mono"></span>
                    </span>
                </div>
            </div>

            <!-- Hidden field for combined cadence -->
            <input type="hidden" name="cadence" id="hidden_cadence" value="{{ $cadence }}">

            <!-- Submit Button -->
            <div class="flex justify-end pt-4 border-t">
                <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2">
                    <i data-lucide="clock" class="w-4 h-4 inline mr-2"></i>
                    Save Schedule
                </button>
            </div>
        </form>
    </div>

    <!-- Current Configuration Summary -->
    <div class="bg-gray-50 rounded-lg p-6">
        <h3 class="text-sm font-semibold text-gray-900 mb-3">Current Configuration</h3>
        <dl class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
                <dt class="text-xs font-medium text-gray-500">Active Services</dt>
                <dd class="mt-1 flex flex-wrap gap-2">
                    @foreach(['dns' => 'DNS', 'spf' => 'SPF', 'blacklist' => 'Blacklist', 'delivery' => 'Delivery'] as $key => $label)
                        @if($enabled[$key] ?? false)
                            <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                <i data-lucide="check-circle" class="w-3 h-3 mr-1"></i>{{ $label }}
                            </span>
                        @endif
                    @endforeach
                </dd>
            </div>
            <div>
                <dt class="text-xs font-medium text-gray-500">Scan Schedule</dt>
                <dd class="mt-1 text-sm text-gray-900">
                    @if($cadence === 'off')
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-800">
                            <i data-lucide="pause-circle" class="w-3 h-3 mr-1"></i>Manual Only
                        </span>
                    @else
                        <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                            <i data-lucide="clock" class="w-3 h-3 mr-1"></i>{{ ucfirst($cadence) }} at {{ $runAt ? substr($runAt, 0, 5) : '09:00' }} UTC
                        </span>
                    @endif
                </dd>
            </div>
        </dl>
    </div>
</div>

<script>
    // Initialize Lucide icons
    lucide.createIcons();

    // Update current UTC time
    function updateUtcTime() {
        const now = new Date();
        const hours = String(now.getUTCHours()).padStart(2, '0');
        const minutes = String(now.getUTCMinutes()).padStart(2, '0');
        document.getElementById('current-utc-time').textContent = `${hours}:${minutes}`;
    }
    updateUtcTime();
    setInterval(updateUtcTime, 60000); // Update every minute

    // Handle schedule type changes
    const scheduleRadios = document.querySelectorAll('input[name="schedule_type"]');
    const timePicker = document.getElementById('time-picker-container');
    
    scheduleRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.value === 'off') {
                timePicker.classList.add('hidden');
            } else {
                timePicker.classList.remove('hidden');
            }
        });
    });

    // Update hidden cadence field before form submission
    document.querySelectorAll('form').forEach(form => {
        form.addEventListener('submit', function(e) {
            const scheduleType = document.querySelector('input[name="schedule_type"]:checked');
            if (scheduleType && form.querySelector('input[name="cadence"]')) {
                let cadenceValue = scheduleType.value;
                if (cadenceValue !== 'off') {
                    const time = document.getElementById('schedule_time').value;
                    cadenceValue = cadenceValue + '@' + time;
                }
                document.getElementById('hidden_cadence').value = cadenceValue;
            }
        });
    });
</script>
@endsection
