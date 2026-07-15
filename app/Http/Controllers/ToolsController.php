<?php

namespace App\Http\Controllers;

use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisReader;
use App\Domain\EmailSecurity\Checks\Bimi\BimiAnalysisService;
use App\Domain\EmailSecurity\Checks\Bimi\Compatibility\BimiLegacyPayloadAdapter;
use App\Domain\EmailSecurity\Checks\DKIM\DkimAnalysisService;
use App\Domain\EmailSecurity\DTO\CheckContextDTO;
use App\Http\Controllers\Controller;
use App\Domain\EmailSecurity\Checks\DKIM\Compatibility\DkimLegacyPayloadAdapter;
use App\Services\Dns\DnsClient;
use App\Services\SmtpTester;
use App\Services\Spf\SpfResolver;
use Illuminate\Http\Request;

class ToolsController extends Controller
{
    public function __construct(
        private DkimAnalysisService $dkimAnalysisService,
        private DkimLegacyPayloadAdapter $dkimLegacyAdapter,
        private BimiAnalysisService $bimiAnalysisService,
        private BimiLegacyPayloadAdapter $bimiLegacyAdapter,
    ) {
        $this->middleware(['auth', 'entitlement:standalone_tools']);
    }

    /**
     * Tools index page.
     */
    public function index()
    {
        return view('tools.index');
    }

    // ── SMTP Test ───────────────────────────────────────────────

    public function smtpTestForm()
    {
        return view('tools.smtp-test');
    }

    public function smtpTest(Request $request, SmtpTester $tester)
    {
        $request->validate([
            'domain' => 'required|string|max:253',
            'port' => 'nullable|integer|in:25,465,587',
        ]);

        $domain = strtolower(trim($request->input('domain')));
        $port = (int) ($request->input('port', 25));

        $results = $tester->test($domain, $port);

        return view('tools.smtp-test', compact('results', 'domain', 'port'));
    }

    // ── BIMI Check ──────────────────────────────────────────────

    public function bimiCheckForm()
    {
        return view('tools.bimi-check');
    }

    public function bimiCheck(Request $request)
    {
        $request->validate([
            'domain' => 'required|string|max:253',
        ]);

        $domain = strtolower(trim($request->input('domain')));

        $context = new CheckContextDTO(
            domainName: $domain,
            domainId: null,
            scanId: null,
            scanType: 'bimi',
            enabledServices: [
                'dns' => true,
                'spf' => false,
                'blacklist' => false,
                'dkim' => false,
                'monitoring' => false,
            ],
            environment: app()->environment(),
            correlationId: 'tools-bimi-' . uniqid(),
            executedAt: now()->toIso8601String(),
        );

        $native = $this->bimiAnalysisService->analyze($context, null);
        $payload = $this->bimiLegacyAdapter->toResultJsonBimi($native);
        $analysis = $payload['analysis'] ?? [];

        $results = [
            'domain' => $domain,
            'record_found' => in_array($analysis['protocol_status'] ?? null, ['valid', 'declined', 'permerror', 'partially_evaluated'], true),
            'raw_record' => $analysis['record']['raw'] ?? null,
            'version' => $analysis['record']['tags']['version'] ?? null,
            'logo_url' => $analysis['record']['tags']['logo_uri'] ?? null,
            'authority_url' => $analysis['record']['tags']['authority_uri'] ?? null,
            'logo_valid' => ($analysis['indicator']['status'] ?? null) === 'valid',
            'logo_content_type' => $analysis['indicator']['fetch']['content_type'] ?? null,
            'logo_size_bytes' => $analysis['indicator']['decompressed_bytes'] ?? null,
            'logo_errors' => array_map(
                fn (array $e) => $e['message'] ?? '',
                is_array($analysis['indicator']['validation_errors'] ?? null) ? $analysis['indicator']['validation_errors'] : [],
            ),
            'protocol_status' => $analysis['protocol_status'] ?? null,
            'readiness_status' => $analysis['readiness_status'] ?? null,
            'summary' => $analysis['summary'] ?? null,
            'declined' => ($analysis['protocol_status'] ?? null) === 'declined',
            'checked_at' => now()->toISOString(),
        ];

        return view('tools.bimi-check', compact('results', 'domain', 'analysis'));
    }

    // ── SPF Wizard ──────────────────────────────────────────────

    public function spfWizardForm()
    {
        $providers = $this->getEmailProviders();
        return view('tools.spf-wizard', compact('providers'));
    }

    public function spfWizard(Request $request, DnsClient $dnsClient)
    {
        $request->validate([
            'domain' => 'required|string|max:253',
            'providers' => 'nullable|array',
            'providers.*' => 'string',
            'custom_ips' => 'nullable|string',
            'custom_includes' => 'nullable|string',
            'qualifier' => 'required|in:-all,~all,?all',
            'use_mx' => 'nullable|boolean',
        ]);

        $domain = strtolower(trim($request->input('domain')));
        $selectedProviders = $request->input('providers', []);
        $qualifier = $request->input('qualifier', '~all');
        $useMx = $request->boolean('use_mx');

        // Build SPF mechanisms
        $mechanisms = [];

        if ($useMx) {
            $mechanisms[] = 'mx';
        }

        // Add provider includes
        $providers = $this->getEmailProviders();
        foreach ($selectedProviders as $key) {
            if (isset($providers[$key])) {
                foreach ($providers[$key]['includes'] as $include) {
                    $mechanisms[] = "include:{$include}";
                }
            }
        }

        // Add custom includes
        $customIncludes = $request->input('custom_includes', '');
        if ($customIncludes) {
            foreach (preg_split('/[\s,]+/', $customIncludes) as $include) {
                $include = trim($include);
                if ($include) {
                    $mechanisms[] = "include:{$include}";
                }
            }
        }

        // Add custom IPs
        $customIps = $request->input('custom_ips', '');
        if ($customIps) {
            foreach (preg_split('/[\s,]+/', $customIps) as $ip) {
                $ip = trim($ip);
                if (!$ip) continue;
                if (str_contains($ip, ':')) {
                    $mechanisms[] = "ip6:{$ip}";
                } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || str_contains($ip, '/')) {
                    $mechanisms[] = "ip4:{$ip}";
                }
            }
        }

        // Build the record
        $spfRecord = 'v=spf1 ' . implode(' ', array_unique($mechanisms)) . ' ' . $qualifier;

        // Count lookups
        $lookupCount = 0;
        if ($useMx) $lookupCount++;
        foreach ($mechanisms as $m) {
            if (str_starts_with($m, 'include:')) $lookupCount++;
        }

        // Get current SPF record for comparison
        $currentTxt = $dnsClient->getTxt($domain);
        $currentSpf = null;
        foreach ($currentTxt as $record) {
            if (str_starts_with(strtolower($record), 'v=spf1')) {
                $currentSpf = $record;
                break;
            }
        }

        $providersConfig = $this->getEmailProviders();

        return view('tools.spf-wizard', [
            'domain' => $domain,
            'providers' => $providersConfig,
            'selectedProviders' => $selectedProviders,
            'qualifier' => $qualifier,
            'useMx' => $useMx,
            'customIps' => $customIps,
            'customIncludes' => $customIncludes,
            'generatedRecord' => $spfRecord,
            'lookupCount' => $lookupCount,
            'currentSpf' => $currentSpf,
        ]);
    }

    // ── DKIM Lookup ─────────────────────────────────────────────

    public function dkimLookupForm()
    {
        return view('tools.dkim-lookup');
    }

    public function dkimLookup(Request $request)
    {
        $request->validate([
            'domain' => 'required|string|max:253',
            'selector' => 'nullable|string|max:253',
            'dkim_signature' => 'nullable|string|max:4096',
        ]);

        $domain = strtolower(trim($request->input('domain')));
        $selectorInput = trim($request->input('selector', ''));
        $signatureInput = trim($request->input('dkim_signature', ''));

        $context = new CheckContextDTO(
            domainName: $domain,
            domainId: null,
            scanId: null,
            scanType: 'dkim',
            enabledServices: [
                'dns' => false,
                'spf' => false,
                'blacklist' => false,
                'dkim' => true,
                'monitoring' => false,
                'dkim_selector' => $selectorInput !== '' ? $selectorInput : null,
                'dkim_signature' => $signatureInput !== '' ? $signatureInput : null,
                'provider_guess' => null,
                'dmarc_expected_rua' => null,
            ],
            environment: app()->environment(),
            correlationId: 'tools-dkim-' . uniqid(),
            executedAt: now()->toIso8601String(),
        );

        $native = $this->dkimAnalysisService->analyze($context);
        $analysis = $this->dkimLegacyAdapter->toResultJsonDkim($native)['analysis'];

        $results = [];
        foreach ($analysis['selectors'] ?? [] as $row) {
            $results[] = [
                'selector' => $row['selector'] ?? 'unknown',
                'dns_name' => $row['hostname'] ?? '',
                'record' => ($row['record_status'] ?? '') === 'valid'
                    ? 'Valid DKIM key record'
                    : ($row['record_status'] ?? 'none'),
                'key_type' => $row['key_type'] ?? null,
                'key_bits' => $row['key_bits'] ?? null,
                'status' => $row['record_status'] ?? 'none',
                'source' => $row['source'] ?? null,
                'errors' => $row['errors'] ?? [],
                'warnings' => $row['warnings'] ?? [],
            ];
        }

        return view('tools.dkim-lookup', compact('domain', 'results', 'selectorInput', 'analysis'));
    }

    /**
     * Known email provider SPF includes.
     */
    private function getEmailProviders(): array
    {
        return [
            'google' => [
                'name' => 'Google Workspace / Gmail',
                'includes' => ['_spf.google.com'],
            ],
            'microsoft' => [
                'name' => 'Microsoft 365 / Outlook',
                'includes' => ['spf.protection.outlook.com'],
            ],
            'sendgrid' => [
                'name' => 'SendGrid',
                'includes' => ['sendgrid.net'],
            ],
            'mailgun' => [
                'name' => 'Mailgun',
                'includes' => ['mailgun.org'],
            ],
            'amazonses' => [
                'name' => 'Amazon SES',
                'includes' => ['amazonses.com'],
            ],
            'postmark' => [
                'name' => 'Postmark',
                'includes' => ['spf.mtasv.net'],
            ],
            'mailchimp' => [
                'name' => 'Mailchimp / Mandrill',
                'includes' => ['spf.mandrillapp.com'],
            ],
            'zoho' => [
                'name' => 'Zoho Mail',
                'includes' => ['zoho.com'],
            ],
            'protonmail' => [
                'name' => 'Proton Mail',
                'includes' => ['_spf.protonmail.ch'],
            ],
            'sparkpost' => [
                'name' => 'SparkPost',
                'includes' => ['sparkpostmail.com'],
            ],
            'sendinblue' => [
                'name' => 'Brevo (Sendinblue)',
                'includes' => ['sendinblue.com'],
            ],
            'freshdesk' => [
                'name' => 'Freshdesk / Freshworks',
                'includes' => ['email.freshdesk.com'],
            ],
        ];
    }
}
