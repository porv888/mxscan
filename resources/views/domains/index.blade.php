@extends('layouts.app')

@section('page-title', 'Domains')

@section('content')
<div class="space-y-6">
    @php 
        $used = auth()->user()->domainsUsed(); 
        $limit = auth()->user()->domainLimit(); 
    @endphp

    <!-- Header -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
            <h1 class="text-2xl font-bold text-gray-900">Domains</h1>
            <p class="text-gray-500 mt-1">{{ $used }} of {{ $limit }} domains used</p>
        </div>
        <div class="flex items-center gap-3">
            @if($used >= $limit)
                <a href="{{ route('pricing') }}" class="text-sm text-blue-600 hover:text-blue-700 font-medium">
                    Upgrade plan
                </a>
            @endif
            <a href="{{ route('dashboard.domains.create') }}" 
               class="{{ $used >= $limit ? 'bg-gray-300 cursor-not-allowed pointer-events-none' : 'bg-blue-600 hover:bg-blue-700' }} text-white px-4 py-2.5 rounded-lg font-medium inline-flex items-center gap-2 transition-colors">
                <i data-lucide="plus" class="w-4 h-4"></i>
                <span>Add Domain</span>
            </a>
        </div>
    </div>

    @if($domains->count() > 0)
        <!-- Domain Cards Grid -->
        <div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            @foreach($domains as $domain)
                @php
                    $latestSpfCheck = $domain->latestSpfCheck;
                    $daysDomain = $domain->getDaysUntilDomainExpiry();
                    $daysSsl = $domain->getDaysUntilSslExpiry();
                    
                    // Determine worst issue for this domain (priority order)
                    $worstIssue = null;
                    $worstSeverity = 'ok';
                    $worstIcon = 'check-circle';
                    $worstAction = null;
                    $worstActionUrl = null;
                    
                    // Priority 1: Blacklisted (critical)
                    if ($domain->blacklist_status === 'listed') {
                        $worstIssue = $domain->blacklist_count . ' blacklist' . ($domain->blacklist_count > 1 ? 's' : '');
                        $worstSeverity = 'critical';
                        $worstIcon = 'shield-alert';
                        $worstAction = 'Delist Now';
                        $latestScan = $domain->scans()->latest()->first();
                        $worstActionUrl = $latestScan ? route('scans.show', $latestScan) : null;
                    }
                    // Priority 2: Low score (critical if <60, warning if <80)
                    elseif ($domain->score_last !== null && $domain->score_last < 60) {
                        $worstIssue = 'Score ' . $domain->score_last . '% - needs attention';
                        $worstSeverity = 'critical';
                        $worstIcon = 'trending-down';
                        $worstAction = 'View Report';
                        $latestScan = $domain->scans()->latest()->first();
                        $worstActionUrl = $latestScan ? route('scans.show', $latestScan) : null;
                    }
                    // Priority 3: Domain/SSL expiring soon
                    elseif (($daysDomain !== null && $daysDomain < 7) || ($daysSsl !== null && $daysSsl < 7)) {
                        $expiringWhat = ($daysDomain !== null && $daysDomain < 7) ? 'Domain' : 'SSL';
                        $expiringDays = ($daysDomain !== null && $daysDomain < 7) ? $daysDomain : $daysSsl;
                        $worstIssue = $expiringWhat . ' expires in ' . $expiringDays . ' days';
                        $worstSeverity = 'critical';
                        $worstIcon = 'calendar-x';
                        $worstAction = 'Renew';
                        $worstActionUrl = route('dashboard.domains.edit', $domain);
                    }
                    // Priority 4: SPF over limit
                    elseif ($latestSpfCheck && $latestSpfCheck->lookup_count >= 10) {
                        $worstIssue = 'SPF exceeds 10 lookups (' . $latestSpfCheck->lookup_count . ')';
                        $worstSeverity = 'warning';
                        $worstIcon = 'mail-warning';
                        $worstAction = 'Fix SPF';
                        $worstActionUrl = route('spf.show', $domain);
                    }
                    // Priority 5: Score warning (60-79)
                    elseif ($domain->score_last !== null && $domain->score_last < 80) {
                        $worstIssue = 'Score ' . $domain->score_last . '% - room to improve';
                        $worstSeverity = 'warning';
                        $worstIcon = 'alert-circle';
                        $worstAction = 'View Report';
                        $latestScan = $domain->scans()->latest()->first();
                        $worstActionUrl = $latestScan ? route('scans.show', $latestScan) : null;
                    }
                    // Priority 6: Expiring within 30 days
                    elseif (($daysDomain !== null && $daysDomain < 30) || ($daysSsl !== null && $daysSsl < 30)) {
                        $expiringWhat = ($daysDomain !== null && $daysDomain < 30) ? 'Domain' : 'SSL';
                        $expiringDays = ($daysDomain !== null && $daysDomain < 30) ? $daysDomain : $daysSsl;
                        $worstIssue = $expiringWhat . ' expires in ' . $expiringDays . ' days';
                        $worstSeverity = 'warning';
                        $worstIcon = 'calendar';
                        $worstAction = 'Renew';
                        $worstActionUrl = route('dashboard.domains.edit', $domain);
                    }
                    // Priority 7: Never scanned
                    elseif (!$domain->scans()->exists()) {
                        $worstIssue = 'Never scanned';
                        $worstSeverity = 'info';
                        $worstIcon = 'scan';
                        $worstAction = 'Scan';
                        $worstActionUrl = null; // Will use form
                    }
                @endphp

                <div class="bg-white rounded-xl border overflow-hidden transition-all duration-200 hover:shadow-md
                    {{ $worstSeverity === 'critical' ? 'border-red-200 hover:border-red-300' : 
                       ($worstSeverity === 'warning' ? 'border-amber-200 hover:border-amber-300' : 
                       'border-gray-200 hover:border-gray-300') }}">
                    
                    <!-- Worst Issue Banner (Main Visual Anchor) -->
                    @if($worstIssue)
                    <div class="px-4 py-2.5 flex items-center justify-between
                        {{ $worstSeverity === 'critical' ? 'bg-red-50' : 
                           ($worstSeverity === 'warning' ? 'bg-amber-50' : 'bg-blue-50') }}">
                        <div class="flex items-center gap-2">
                            <i data-lucide="{{ $worstIcon }}" class="w-4 h-4 
                                {{ $worstSeverity === 'critical' ? 'text-red-600' : 
                                   ($worstSeverity === 'warning' ? 'text-amber-600' : 'text-blue-600') }}"></i>
                            <span class="text-sm font-medium 
                                {{ $worstSeverity === 'critical' ? 'text-red-800' : 
                                   ($worstSeverity === 'warning' ? 'text-amber-800' : 'text-blue-800') }}">
                                {{ $worstIssue }}
                            </span>
                        </div>
                        @if($worstAction && $worstActionUrl)
                            <a href="{{ $worstActionUrl }}" class="text-xs font-semibold px-2 py-1 rounded transition-colors
                                {{ $worstSeverity === 'critical' ? 'bg-red-600 hover:bg-red-700 text-white' : 
                                   ($worstSeverity === 'warning' ? 'bg-amber-600 hover:bg-amber-700 text-white' : 'bg-blue-600 hover:bg-blue-700 text-white') }}">
                                {{ $worstAction }}
                            </a>
                        @elseif($worstAction === 'Scan')
                            <form action="{{ route('domains.scan.now', $domain) }}" method="POST" class="inline">
                                @csrf
                                <input type="hidden" name="mode" value="full">
                                <button type="submit" class="text-xs font-semibold px-2 py-1 rounded bg-blue-600 hover:bg-blue-700 text-white transition-colors">
                                    {{ $worstAction }}
                                </button>
                            </form>
                        @endif
                    </div>
                    @else
                    <!-- All Good Banner -->
                    <div class="px-4 py-2.5 bg-green-50 flex items-center gap-2">
                        <i data-lucide="check-circle" class="w-4 h-4 text-green-600"></i>
                        <span class="text-sm font-medium text-green-800">All checks passed</span>
                    </div>
                    @endif

                    <!-- Card Header (Compact) -->
                    <div class="p-4">
                        <div class="flex items-center justify-between gap-3">
                            <div class="flex items-center gap-3 min-w-0">
                                <!-- Score Circle (smaller) -->
                                <div class="flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center text-sm font-bold
                                    @if($domain->score_last)
                                        @if($domain->score_last >= 80) bg-green-100 text-green-700
                                        @elseif($domain->score_last >= 60) bg-yellow-100 text-yellow-700
                                        @else bg-red-100 text-red-700 @endif
                                    @else bg-gray-100 text-gray-400 @endif">
                                    {{ $domain->score_last ?? '—' }}
                                </div>
                                <!-- Domain Name -->
                                <div class="min-w-0">
                                    @if($domain->scans()->exists())
                                        @php $latestScanForLink = $domain->scans()->latest()->first(); @endphp
                                        <a href="{{ route('scans.show', $latestScanForLink) }}" class="font-semibold text-gray-900 hover:text-blue-600 truncate block transition-colors">
                                            {{ $domain->domain }}
                                        </a>
                                    @else
                                        <h3 class="font-semibold text-gray-900 truncate">{{ $domain->domain }}</h3>
                                    @endif
                                    <p class="text-xs text-gray-500">{{ $domain->provider_guess ?: 'Unknown provider' }}</p>
                                </div>
                            </div>
                            <!-- Actions Menu -->
                            <div class="relative flex-shrink-0" x-data="{ open: false }">
                                <button @click="open = !open" class="p-1.5 text-gray-400 hover:text-gray-600 hover:bg-gray-100 rounded-lg transition-colors">
                                    <i data-lucide="more-vertical" class="w-4 h-4"></i>
                                </button>
                                <div x-show="open" @click.away="open = false" x-cloak
                                     x-transition:enter="transition ease-out duration-100"
                                     x-transition:enter-start="transform opacity-0 scale-95"
                                     x-transition:enter-end="transform opacity-100 scale-100"
                                     x-transition:leave="transition ease-in duration-75"
                                     x-transition:leave-start="transform opacity-100 scale-100"
                                     x-transition:leave-end="transform opacity-0 scale-95"
                                     class="absolute right-0 mt-1 w-48 bg-white rounded-lg shadow-lg border border-gray-200 py-1 z-20">
                                    <a href="{{ route('dashboard.domains.edit', $domain) }}" 
                                       class="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                                        <i data-lucide="settings" class="w-4 h-4"></i>
                                        Settings
                                    </a>
                                    <a href="{{ route('spf.show', $domain) }}" 
                                       class="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                                        <i data-lucide="shield" class="w-4 h-4"></i>
                                        SPF Analysis
                                    </a>
                                    @if($domain->scans()->exists())
                                        <a href="{{ route('reports.index', ['domain_id' => $domain->id]) }}" 
                                           class="flex items-center gap-2 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                                            <i data-lucide="file-text" class="w-4 h-4"></i>
                                            View Reports
                                        </a>
                                    @endif
                                    <div class="border-t border-gray-100 my-1"></div>
                                    <button type="button"
                                            onclick="showDeleteModal('{{ $domain->domain }}', {{ $domain->id }})"
                                            data-delete-url="{{ route('dashboard.domains.destroy', $domain) }}"
                                            class="flex items-center gap-2 w-full px-3 py-2 text-sm text-red-600 hover:bg-red-50">
                                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                                        Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Card Footer - Simplified Actions -->
                    <div class="p-3 border-t border-gray-100 flex items-center gap-2">
                        <!-- Primary Scan Button -->
                        <form action="{{ route('domains.scan.now', $domain) }}" method="POST" class="flex-1">
                            @csrf
                            <input type="hidden" name="mode" value="full">
                            <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white px-3 py-2 rounded-lg text-sm font-medium inline-flex items-center justify-center gap-2 transition-colors">
                                <i data-lucide="scan" class="w-4 h-4"></i>
                                Scan
                            </button>
                        </form>
                        
                        <!-- Scan Options Dropdown -->
                        <div class="relative" x-data="{ open: false }">
                            <button @click="open = !open" 
                                    class="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors border border-gray-200">
                                <i data-lucide="chevron-down" class="w-4 h-4"></i>
                            </button>
                            <div x-show="open" @click.away="open = false" x-cloak
                                 x-transition:enter="transition ease-out duration-100"
                                 x-transition:enter-start="transform opacity-0 scale-95"
                                 x-transition:enter-end="transform opacity-100 scale-100"
                                 class="absolute right-0 bottom-full mb-1 w-44 bg-white rounded-lg shadow-lg border border-gray-200 py-1 z-20">
                                <div class="px-3 py-1.5 text-xs font-medium text-gray-400 uppercase tracking-wider">Scan Type</div>
                                <form action="{{ route('domains.scan.now', $domain) }}" method="POST">
                                    @csrf
                                    <input type="hidden" name="mode" value="dns">
                                    <button type="submit" class="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                                        <i data-lucide="globe" class="w-4 h-4"></i>
                                        DNS Only
                                    </button>
                                </form>
                                <form action="{{ route('domains.scan.now', $domain) }}" method="POST">
                                    @csrf
                                    <input type="hidden" name="mode" value="spf">
                                    <button type="submit" class="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                                        <i data-lucide="mail" class="w-4 h-4"></i>
                                        SPF Only
                                    </button>
                                </form>
                                @if(auth()->user()->can('blacklist', $domain))
                                    <form action="{{ route('domains.scan.now', $domain) }}" method="POST">
                                        @csrf
                                        <input type="hidden" name="mode" value="blacklist">
                                        <button type="submit" class="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-700 hover:bg-gray-50">
                                            <i data-lucide="shield-check" class="w-4 h-4"></i>
                                            Blacklist Only
                                        </button>
                                    </form>
                                @else
                                    <button type="button" class="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-400 cursor-not-allowed">
                                        <i data-lucide="lock" class="w-4 h-4"></i>
                                        Blacklist Only
                                        <span class="ml-auto text-xs bg-gray-100 px-1.5 py-0.5 rounded">Pro</span>
                                    </button>
                                @endif
                            </div>
                        </div>

                        <!-- View Latest Report -->
                        @if($domain->scans()->exists())
                            @php $latestScan = $domain->scans()->latest()->first(); @endphp
                            <a href="{{ route('scans.show', $latestScan) }}" 
                               class="p-2 text-gray-600 hover:text-gray-900 hover:bg-gray-100 rounded-lg transition-colors border border-gray-200"
                               title="View Latest Report">
                                <i data-lucide="file-text" class="w-4 h-4"></i>
                            </a>
                        @endif
                    </div>
                </div>
            @endforeach
        </div>
    @else
        <!-- Empty State -->
        <div class="bg-white rounded-xl border border-gray-200 p-12 text-center">
            <div class="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                <i data-lucide="globe" class="w-8 h-8 text-blue-600"></i>
            </div>
            <h3 class="text-lg font-semibold text-gray-900">No domains yet</h3>
            <p class="mt-2 text-gray-500 max-w-sm mx-auto">Add your first domain to start monitoring email security, blacklist status, and more.</p>
            <a href="{{ route('dashboard.domains.create') }}" 
               class="mt-6 inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg font-medium transition-colors">
                <i data-lucide="plus" class="w-4 h-4"></i>
                Add Your First Domain
            </a>
        </div>
    @endif
</div>

<!-- Schedule Scan Modal -->
<div id="scheduleModal" class="fixed inset-0 bg-gray-600 bg-opacity-50 hidden z-50">
    <div class="flex items-center justify-center min-h-screen p-4">
        <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
            <form id="scheduleForm" action="#" method="POST">
                @csrf
                <div class="px-6 py-4 border-b border-gray-200">
                    <h3 class="text-lg font-medium text-gray-900">Schedule Scans</h3>
                    <p class="mt-1 text-sm text-gray-600">Configure automated scanning for <span id="scheduleDomainName"></span></p>
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
                        <h3 class="text-lg font-medium text-gray-900">Delete Domain</h3>
                        <p class="mt-2 text-sm text-gray-500">
                            Are you sure you want to delete <strong id="deleteDomainName"></strong>? 
                            This action cannot be undone and will remove all associated scan data.
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
                        Delete Domain
                    </button>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
    function openAddDomainModal() {
        document.getElementById('addDomainModal').classList.remove('hidden');
        document.getElementById('addDomainModal').__x.$data.show = true;
    }
    
    function confirmDelete(domainId, domainName) {
        document.getElementById('deleteDomainName').textContent = domainName;
        document.getElementById('deleteForm').action = `#`; // Will be handled by deleteDomain function
        document.getElementById('deleteModal').classList.remove('hidden');
        document.getElementById('deleteModal').__x.$data.show = true;
    }
    
    function addDomain(event) {
        event.preventDefault();
        // This would normally submit to a controller
        // For now, just show success message
        alert('Domain would be added via controller');
    }
    
    function showScheduleModal(domainId) {
        // Find the button that was clicked
        const button = document.querySelector(`button[onclick="showScheduleModal(${domainId})"]`);
        const scheduleUrl = button.getAttribute('data-schedule-url');
        const domainName = button.getAttribute('data-domain-name');
        
        // Update the modal
        const modal = document.getElementById('scheduleModal');
        const form = document.getElementById('scheduleForm');
        const domainNameSpan = document.getElementById('scheduleDomainName');
        
        form.action = scheduleUrl;
        domainNameSpan.textContent = domainName;
        modal.classList.remove('hidden');
    }
    
    function hideScheduleModal() {
        document.getElementById('scheduleModal').classList.add('hidden');
    }
    
    function showDeleteModal(domainName, domainId) {
        const button = document.querySelector(`button[onclick="showDeleteModal('${domainName}', ${domainId})"]`);
        const deleteUrl = button.getAttribute('data-delete-url');
        
        document.getElementById('deleteDomainName').textContent = domainName;
        document.getElementById('deleteForm').action = deleteUrl;
        document.getElementById('deleteModal').classList.remove('hidden');
    }
    
    function hideDeleteModal() {
        document.getElementById('deleteModal').classList.add('hidden');
    }
</script>
@endsection
