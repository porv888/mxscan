{{-- Fix Pack - Actionable recommendations sorted by impact --}}
<div id="fix-pack" class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-6">
    <h2 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-4">Recommended Fixes</h2>
    
    <div class="space-y-4">
        {{-- Priority 1: Blacklist Delisting --}}
        @if($blacklistHits > 0)
        <div class="pb-4 border-b border-gray-200 dark:border-gray-700">
            <div class="flex items-start mb-3">
                <div class="flex-shrink-0 w-8 h-8 bg-red-100 dark:bg-red-900/50 rounded-lg flex items-center justify-center mr-3">
                    <span class="text-sm font-bold text-red-600 dark:text-red-400">1</span>
                </div>
                <div class="flex-1">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">Remove from Blacklists</h3>
                    <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">Your mail servers are listed on {{ $blacklistHits }} blacklist(s). This severely impacts email deliverability.</p>
                    <a href="#blacklist-section" class="inline-flex items-center px-3 py-1.5 text-xs font-medium text-white bg-red-600 rounded-md hover:bg-red-700 dark:bg-red-700 dark:hover:bg-red-600 transition-colors">
                        <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path>
                        </svg>
                        View Delist Links
                    </a>
                </div>
            </div>
        </div>
        @endif

        {{-- Priority 2: DMARC Policy --}}
        @if(!$dmarcPolicy || $dmarcPolicy === 'none')
        <div class="pb-4 border-b border-gray-200 dark:border-gray-700">
            <div class="flex items-start mb-3">
                <div class="flex-shrink-0 w-8 h-8 bg-amber-100 dark:bg-amber-900/50 rounded-lg flex items-center justify-center mr-3">
                    <span class="text-sm font-bold text-amber-600 dark:text-amber-400">{{ $blacklistHits > 0 ? '2' : '1' }}</span>
                </div>
                <div class="flex-1">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">
                        {{ $dmarcPolicy ? 'Upgrade DMARC Policy' : 'Add DMARC Policy' }}
                    </h3>
                    <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">
                        {{ $dmarcPolicy === 'none' ? 'Your DMARC policy is set to "none" which provides no protection. Upgrade to "quarantine" or "reject".' : 'DMARC protects your domain from email spoofing and phishing attacks.' }}
                    </p>
                    @if($dmarcPolicy === 'none')
                    <x-copy-row 
                        label="Upgrade to Quarantine" 
                        value="v=DMARC1; p=quarantine; rua=mailto:dmarc@{{ $domain->domain }}; pct=100; adkim=r; aspf=r;" 
                    />
                    @else
                    <x-copy-row 
                        label="Add DMARC Record (_dmarc.{{ $domain->domain }})" 
                        value="v=DMARC1; p=quarantine; rua=mailto:dmarc@{{ $domain->domain }}; pct=100; adkim=r; aspf=r;" 
                        action="https://dmarc.org/overview/"
                    />
                    @endif
                </div>
            </div>
        </div>
        @endif

        {{-- Priority 3: SPF Optimization --}}
        @if($spfLookupCount >= 7 && $spfSuggestion)
        <div class="pb-4 border-b border-gray-200 dark:border-gray-700">
            <div class="flex items-start mb-3">
                <div class="flex-shrink-0 w-8 h-8 bg-blue-100 dark:bg-blue-900/50 rounded-lg flex items-center justify-center mr-3">
                    <span class="text-sm font-bold text-blue-600 dark:text-blue-400">{{ ($blacklistHits > 0 ? 1 : 0) + (!$dmarcPolicy || $dmarcPolicy === 'none' ? 1 : 0) + 1 }}</span>
                </div>
                <div class="flex-1">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">Flatten SPF Record</h3>
                    <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">
                        Your SPF record uses {{ $spfLookupCount }}/10 DNS lookups. 
                        @if($spfLookupCount >= 10)
                        <span class="text-red-600 dark:text-red-400 font-medium">This exceeds the RFC limit and will cause delivery failures!</span>
                        @else
                        Flatten it to improve reliability.
                        @endif
                    </p>
                    <x-copy-row 
                        label="Flattened SPF Record" 
                        value="{{ $spfSuggestion }}" 
                    />
                    <div class="mt-2 text-xs text-gray-500 dark:text-gray-400">
                        <a href="{{ route('spf.show', $domain) }}" class="text-blue-600 dark:text-blue-400 hover:underline">View full SPF analysis →</a>
                    </div>
                </div>
            </div>
        </div>
        @endif

        {{-- Priority 4: TLS-RPT --}}
        @if(!$tlsrptOk)
        <div class="pb-4 border-b border-gray-200 dark:border-gray-700">
            <div class="flex items-start mb-3">
                <div class="flex-shrink-0 w-8 h-8 bg-gray-100 dark:bg-gray-700 rounded-lg flex items-center justify-center mr-3">
                    <span class="text-sm font-bold text-gray-600 dark:text-gray-400">{{ ($blacklistHits > 0 ? 1 : 0) + (!$dmarcPolicy || $dmarcPolicy === 'none' ? 1 : 0) + ($spfLookupCount >= 7 ? 1 : 0) + 1 }}</span>
                </div>
                <div class="flex-1">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">Add TLS-RPT Record</h3>
                    <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">Get reports about TLS connection failures to your mail servers.</p>
                    <x-copy-row 
                        label="TLS-RPT Record (_smtp._tls.{{ $domain->domain }})" 
                        value="v=TLSRPTv1; rua=mailto:tlsrpt@{{ $domain->domain }}" 
                        action="https://tools.ietf.org/html/rfc8460"
                    />
                </div>
            </div>
        </div>
        @endif

        {{-- Priority 5: MTA-STS --}}
        @if(!$mtastsOk)
        <div class="pb-4">
            <div class="flex items-start mb-3">
                <div class="flex-shrink-0 w-8 h-8 bg-gray-100 dark:bg-gray-700 rounded-lg flex items-center justify-center mr-3">
                    <span class="text-sm font-bold text-gray-600 dark:text-gray-400">{{ ($blacklistHits > 0 ? 1 : 0) + (!$dmarcPolicy || $dmarcPolicy === 'none' ? 1 : 0) + ($spfLookupCount >= 7 ? 1 : 0) + (!$tlsrptOk ? 1 : 0) + 1 }}</span>
                </div>
                <div class="flex-1">
                    <h3 class="text-sm font-semibold text-gray-900 dark:text-gray-100 mb-1">Add MTA-STS Policy</h3>
                    <p class="text-xs text-gray-600 dark:text-gray-400 mb-3">Enforce TLS encryption for all incoming email connections.</p>
                    
                    <div class="space-y-3">
                        <x-copy-row 
                            label="DNS Record (_mta-sts.{{ $domain->domain }})" 
                            value="v=STSv1; id={{ date('Ymd') }}01" 
                        />
                        
                        <div x-data="{ expanded: false }" class="mt-3">
                            <button @click="expanded = !expanded" class="text-xs text-blue-600 dark:text-blue-400 hover:underline flex items-center">
                                <svg class="w-4 h-4 mr-1 transition-transform" :class="{ 'rotate-90': expanded }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path>
                                </svg>
                                <span x-text="expanded ? 'Hide' : 'Show'"></span> policy file content
                            </button>
                            
                            <div x-show="expanded" x-cloak class="mt-2">
                                <x-copy-row 
                                    label="Create file: https://mta-sts.{{ $domain->domain }}/.well-known/mta-sts.txt" 
                                    value="version: STSv1
mode: enforce
mx: *.{{ $domain->domain }}
max_age: 86400" 
                                    action="https://tools.ietf.org/html/rfc8461"
                                />
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        @endif

        {{-- No fixes needed --}}
        @if($blacklistHits === 0 && $dmarcPolicy && $dmarcPolicy !== 'none' && $spfLookupCount < 7 && $tlsrptOk && $mtastsOk)
        <div class="text-center py-8">
            <svg class="w-16 h-16 mx-auto text-green-500 dark:text-green-400 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
            </svg>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-gray-100 mb-1">All Clear!</h3>
            <p class="text-sm text-gray-600 dark:text-gray-400">No critical fixes needed. Your email security is well configured.</p>
        </div>
        @endif
    </div>
</div>

{{-- Renewal Reminders Card --}}
<div class="mt-6 rounded-xl border border-gray-200 dark:border-gray-700 p-4 bg-white dark:bg-gray-800">
    <div class="text-sm font-medium text-gray-900 dark:text-gray-100 mb-3">Renewal Reminders</div>
    <ul class="text-sm text-gray-600 dark:text-gray-300 space-y-2">
        <li class="flex items-center justify-between">
            <span>Domain:</span>
            <span class="font-medium {{ ($domainDays ?? 0) < 7 ? 'text-red-600 dark:text-red-400' : (($domainDays ?? 0) < 30 ? 'text-amber-600 dark:text-amber-400' : 'text-green-700 dark:text-green-300') }}">
                {{ $domainDays !== null ? $domainDays.' days' : 'unknown' }}
            </span>
        </li>
        <li class="flex items-center justify-between">
            <span>SSL:</span>
            <span class="font-medium {{ ($sslDays ?? 0) < 7 ? 'text-red-600 dark:text-red-400' : (($sslDays ?? 0) < 30 ? 'text-amber-600 dark:text-amber-400' : 'text-green-700 dark:text-green-300') }}">
                {{ $sslDays !== null ? $sslDays.' days' : 'unknown' }}
            </span>
        </li>
    </ul>
    <a href="{{ route('domains.hub.settings', $domain) }}#renewals" class="mt-3 inline-block text-xs text-blue-700 dark:text-blue-300 underline hover:no-underline">Edit dates</a>
</div>
