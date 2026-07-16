@php
    $servers = $row['detail']['detectedMailServers'] ?? [];
    $providers = $technicalRemediation['sender_providers'] ?? [];
    $initialSpf = $technicalRemediation['spf'] ?? [];
@endphp

<div class="mx-spf-builder" data-spf-remediation-builder>
    <nav class="mx-spf-step-nav" aria-label="SPF remediation steps">
        <button type="button" @click="spfStep = 1" :aria-current="spfStep === 1 ? 'step' : null">1. Confirm senders</button>
        <button type="button" @click="spfStep = 2" :disabled="!spf.record" :aria-current="spfStep === 2 ? 'step' : null">2. Review SPF record</button>
        <button type="button" @click="spfStep = 3" :disabled="!spf.record" :aria-current="spfStep === 3 ? 'step' : null">3. Publish and verify</button>
    </nav>

    <section class="mx-spf-step-panel" x-show="spfStep === 1">
    <div class="mx-spf-step">
        <h5>Step 1 — Confirm who sends email</h5>
        <p>Inbound MX records do not prove which servers send outgoing email. Confirm each detected sender before publishing SPF.</p>
    </div>

    @if($servers !== [])
        <h5>Detected infrastructure — confirmation required</h5>
    @endif

    @forelse($servers as $server)
        <article class="mx-detected-sender" data-sender-confidence="pending">
            <div>
                <span class="mx-confidence-badge">Likely · confirmation required</span>
                <h6>Detected mail server</h6>
                <strong>{{ $server['hostname'] }}</strong>
                @foreach($server['ipv4'] as $ip)
                    <code>IPv4: {{ $ip }}</code>
                @endforeach
                @foreach($server['ipv6'] as $ip)
                    <code>IPv6: {{ $ip }}</code>
                @endforeach
            </div>
            <div>
                <p>Does this server also send outgoing email for this domain?</p>
                <div class="mx-tech-action-row">
                    <button type="button" class="mx-btn mx-btn-primary" @click="setServer({{ \Illuminate\Support\Js::from($server) }}, 'confirmed')">Yes, it sends email</button>
                    <button type="button" class="mx-btn mx-btn-secondary" @click="setServer({{ \Illuminate\Support\Js::from($server) }}, 'rejected')">No</button>
                    <button type="button" class="mx-btn mx-btn-ghost" @click="setServer({{ \Illuminate\Support\Js::from($server) }}, 'pending')">I'm not sure</button>
                </div>
            </div>
        </article>
    @empty
        <div class="mx-tech-empty-state">
            <strong>No sending infrastructure has been identified.</strong>
            <p>Select a provider or add your own server IP to build SPF.</p>
        </div>
    @endforelse

    <div class="mx-spf-provider-picker">
        <button type="button" class="mx-btn mx-btn-secondary" @click="showProviderPicker = !showProviderPicker" :aria-expanded="showProviderPicker.toString()">
            Add email service
        </button>
        <div x-show="showProviderPicker" x-collapse class="mx-spf-provider-selector">
            <label for="spf-email-provider-search">Search email services</label>
            <input id="spf-email-provider-search" type="search" x-model="providerSearch" placeholder="Google Workspace, Microsoft 365, Brevo…">
            <div class="mx-spf-provider-results" role="list">
                <template x-for="(provider, key) in providers" :key="key">
                    <button type="button"
                            class="mx-btn mx-btn-secondary"
                            x-show="!providerSearch || provider.name.toLowerCase().includes(providerSearch.toLowerCase())"
                            @click="toggleProvider(key, true); showProviderPicker = false">
                        <span x-text="provider.name"></span>
                    </button>
                </template>
            </div>
        </div>
        <div class="mx-custom-sender-input">
            <input type="text" x-model="customIp" placeholder="Own server IPv4 or IPv6 address" aria-label="Own server IP address" aria-describedby="spf-remediation-error">
            <button type="button" class="mx-btn mx-btn-secondary" @click="addCustomSender()">Add custom server</button>
        </div>
        <div class="mx-custom-sender-input">
            <input type="text" x-model="customInclude" placeholder="Custom SPF include, for example _spf.example.com" aria-label="Custom SPF include" aria-describedby="spf-remediation-error">
            <button type="button" class="mx-btn mx-btn-secondary" @click="addCustomInclude()">Add custom SPF include</button>
        </div>
        <button type="button" class="mx-btn mx-btn-primary" @click="spfStep = 2" :disabled="!spf.record">Review SPF record</button>
    </div>
    </section>

    <section class="mx-spf-step-panel" x-show="spfStep === 2">
    <div class="mx-spf-generated-record report-generated-record">
        <div class="mx-spf-record-heading">
            <div>
                <h5 x-text="spf.state || 'Cannot generate yet'">{{ $initialSpf['state'] ?? 'Cannot generate yet' }}</h5>
                <p x-text="spf.record ? (spf.policy === '-all' ? 'Validated SPF record' : 'Suggested starting SPF record') : 'Build your SPF record by confirming a sender.'"></p>
            </div>
            <strong x-text="spf.record ? (spf.score + '/20') : 'Up to 20 points'">{{ !empty($initialSpf['record']) ? (($initialSpf['score'] ?? 0) . '/20') : 'Up to 20 points' }}</strong>
        </div>

        <template x-if="spf.record">
            <div class="mx-dns-solution-record">
                <h5>Suggested SPF record</h5>
                <dl class="mx-dns-solution-fields">
                    <div><dt>Type</dt><dd>TXT</dd></div>
                    <div><dt>Host</dt><dd><code>@</code></dd></div>
                    <div><dt>TTL</dt><dd>Auto</dd></div>
                    <div class="mx-dns-solution-value"><dt>Value</dt><dd><code x-text="spf.record">{{ $initialSpf['record'] ?? '' }}</code></dd></div>
                </dl>
                <div class="mx-tech-action-row">
                    <button type="button" class="mx-btn mx-btn-primary" @click="copy(spf.record)">Copy value</button>
                    <button type="button" class="mx-btn mx-btn-secondary" @click="copy('TXT @ ' + spf.record)">Copy full record</button>
                </div>
                <p class="mx-copy-feedback" aria-live="polite" x-text="copyStatus"></p>
            </div>
        </template>

        <div class="mx-spf-policy-options">
            <label>
                <input type="radio" x-model="policy" value="~all" @change="preview()">
                <span><strong>Keep soft fail: ~all</strong> — 15/20</span>
            </label>
            <label :class="{ 'opacity-50': !spf.all_senders_resolved }">
                <input type="radio" x-model="policy" value="-all" :disabled="!spf.all_senders_resolved" @change="preview()">
                <span><strong>Enforce hard fail: -all</strong> — 20/20</span>
            </label>
            <p x-show="!spf.all_senders_resolved">Hard fail becomes available after every detected sender is confirmed or rejected.</p>
        </div>

        <div class="mx-spf-validation" :class="spf.errors && spf.errors.length ? 'mx-spf-validation--warning' : 'mx-spf-validation--ready'">
            <strong x-text="spf.errors && spf.errors.length ? 'Needs attention' : (spf.record ? spf.state : 'Cannot generate yet')"></strong>
            <ul>
                <li x-show="spf.record">Syntax valid</li>
                <li x-show="spf.record"><span x-text="spf.mechanisms ? spf.mechanisms.length : 0"></span> authorized mechanisms</li>
                <li x-show="spf.record"><span x-text="spf.lookup_count || 0"></span> DNS lookups</li>
                <li x-show="spf.record">No duplicate mechanisms</li>
                <li x-show="spf.record"><span x-text="'Terminal policy: ' + spf.policy"></span></li>
                <li x-show="spf.record">Unsafe +all check passed</li>
                <li x-show="spf.record"><span x-text="'Record length: ' + spf.record.length + ' characters'"></span></li>
                <template x-for="error in (spf.errors || [])" :key="error.code"><li x-text="error.message"></li></template>
                <template x-for="warning in (spf.warnings || [])" :key="warning.code"><li x-text="warning.message"></li></template>
            </ul>
        </div>

        <p class="mx-tech-supporting-note">This record authorizes only the sending infrastructure you confirmed. Add every external service that sends email using this domain before publishing it.</p>
        <p class="mx-tech-score-gain">Estimated score after publishing: <strong x-text="spf.record ? (spf.score + '/20') : 'Up to 20/20'">{{ !empty($initialSpf['record']) ? (($initialSpf['score'] ?? 0) . '/20') : 'Up to 20/20' }}</strong></p>
        <button type="button" class="mx-btn mx-btn-primary" @click="spfStep = 3" :disabled="!spf.record">Continue to publishing</button>
    </div>
    </section>

    <section class="mx-spf-step-panel" x-show="spfStep === 3">
    <h5>Step 3 — Publish and verify</h5>
    <x-report.dns-provider-instructions
        :providers="$technicalRemediation['dns_providers'] ?? []"
        :selected="$technicalRemediation['dns_provider'] ?? null"
    />

    <p id="spf-remediation-error" class="mx-form-error" role="alert" aria-live="polite" x-show="saveError" x-text="saveError" x-cloak></p>
    <x-report.mobile-action-bar class="mx-tech-action-row">
        <button type="button" class="mx-btn mx-btn-secondary" @click="save()" :disabled="saving">
            <span x-text="saving ? 'Saving…' : 'Save sender choices'">Save sender choices</span>
        </button>
        <x-report.rescan-button />
    </x-report.mobile-action-bar>
    </section>
</div>
