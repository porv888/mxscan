@props(['domain'])

<div id="scheduleModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <form action="{{ route('domains.schedule', $domain->id) }}" method="POST">
                @csrf
                <div class="px-6 py-4 border-b border-gray-200">
                    <h3 class="text-lg font-medium text-gray-900">Schedule Scans</h3>
                    <p class="mt-1 text-sm text-gray-600">Configure automated scanning for {{ $domain->domain }}</p>
                </div>
                
                <div class="px-6 py-4 space-y-4">
                    <!-- Scan Frequency -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">Scan Frequency</label>
                        <select name="frequency" class="w-full border border-gray-300 rounded-md px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                            <option value="disabled">Disabled</option>
                            <option value="daily">Daily</option>
                            <option value="weekly">Weekly</option>
                            <option value="monthly">Monthly</option>
                        </select>
                    </div>
                    
                    <!-- Scan Types -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-3">Scan Types</label>
                        <div class="space-y-3">
                            <!-- Email Security Scan -->
                            <div class="flex items-start">
                                <div class="flex items-center h-5">
                                    <input id="email_security" name="scan_types[]" value="email_security" type="checkbox" 
                                           checked class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded">
                                </div>
                                <div class="ml-3 text-sm">
                                    <label for="email_security" class="font-medium text-gray-700">Email Security Scan</label>
                                    <p class="text-gray-500">Check MX, SPF, DMARC, TLS-RPT, and MTA-STS records</p>
                                </div>
                            </div>
                            
                            <!-- Blacklist Monitoring -->
                            <div class="flex items-start">
                                <div class="flex items-center h-5">
                                    <input id="blacklist_monitoring" name="scan_types[]" value="blacklist_monitoring" type="checkbox" 
                                           class="focus:ring-blue-500 h-4 w-4 text-blue-600 border-gray-300 rounded">
                                </div>
                                <div class="ml-3 text-sm">
                                    <label for="blacklist_monitoring" class="font-medium text-gray-700">Blacklist Monitoring</label>
                                    <p class="text-gray-500">Check domain IPs against spam blacklists (slower)</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <!-- Pro Plan Notice -->
                    <div class="bg-blue-50 border border-blue-200 rounded-lg p-3">
                        <div class="flex items-start">
                            <i data-lucide="info" class="w-5 h-5 text-blue-600 mt-0.5 mr-2 flex-shrink-0"></i>
                            <div class="text-sm">
                                <p class="text-blue-800 font-medium">Pro Plan Feature</p>
                                <p class="text-blue-700">Blacklist monitoring in scheduled scans requires a Pro plan subscription.</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="px-6 py-4 border-t border-gray-200 flex justify-end space-x-3">
                    <button type="button" onclick="hideScheduleModal()" 
                            class="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 hover:bg-gray-200 rounded-md">
                        Cancel
                    </button>
                    <button type="submit" 
                            class="px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 rounded-md">
                        Save Schedule
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function showScheduleModal() {
    document.getElementById('scheduleModal').classList.remove('hidden');
}

function hideScheduleModal() {
    document.getElementById('scheduleModal').classList.add('hidden');
}
</script>