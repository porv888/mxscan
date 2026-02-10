<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Services\BimiChecker;
use App\Services\Dns\DnsClient;
use App\Services\SmtpTester;
use App\Services\Spf\SpfResolver;
use Illuminate\Http\Request;

class ToolsController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
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

    public function bimiCheck(Request $request, BimiChecker $checker)
    {
        $request->validate([
            'domain' => 'required|string|max:253',
        ]);

        $domain = strtolower(trim($request->input('domain')));
        $results = $checker->check($domain);

        return view('tools.bimi-check', compact('results', 'domain'));
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
        ]);

        $domain = strtolower(trim($request->input('domain')));
        $selectorInput = trim($request->input('selector', ''));

        $selectors = $selectorInput ? [$selectorInput] : config('dkim.selectors', []);
        $results = [];

        foreach ($selectors as $sel) {
            try {
                $dnsName = "{$sel}._domainkey.{$domain}";
                $found = false;

                // Try TXT lookup first
                $records = @dns_get_record($dnsName, DNS_TXT);
                if (!empty($records)) {
                    foreach ($records as $rec) {
                        if (isset($rec['txt']) && str_contains($rec['txt'], 'p=')) {
                            $keyInfo = $this->parseDkimPublicKey($rec['txt']);
                            $results[] = [
                                'selector' => $sel,
                                'dns_name' => $dnsName,
                                'record' => $rec['txt'],
                                'key_type' => $keyInfo['type'],
                                'key_bits' => $keyInfo['bits'],
                                'status' => $this->dkimKeyStatus($keyInfo),
                            ];
                            $found = true;
                            break;
                        }
                    }
                }

                // Fallback: check for CNAME (Mandrill, SendGrid, etc.)
                if (!$found) {
                    $cnameRecords = @dns_get_record($dnsName, DNS_CNAME);
                    if (!empty($cnameRecords)) {
                        $target = $cnameRecords[0]['target'] ?? '';
                        $targetTxt = @dns_get_record($target, DNS_TXT);
                        $txtValue = '';
                        if (!empty($targetTxt)) {
                            foreach ($targetTxt as $rec) {
                                if (isset($rec['txt']) && str_contains($rec['txt'], 'p=')) {
                                    $txtValue = $rec['txt'];
                                    break;
                                }
                            }
                        }
                        $keyInfo = $txtValue ? $this->parseDkimPublicKey($txtValue) : ['type' => 'unknown', 'bits' => 0];
                        $results[] = [
                            'selector' => $sel,
                            'dns_name' => $dnsName,
                            'record' => $txtValue ?: "CNAME → {$target}",
                            'key_type' => $keyInfo['type'],
                            'key_bits' => $keyInfo['bits'],
                            'status' => $txtValue ? $this->dkimKeyStatus($keyInfo) : 'cname',
                            'cname_target' => $target,
                        ];
                    }
                }
            } catch (\Exception $e) {
                // Skip failed lookups
            }
        }

        return view('tools.dkim-lookup', compact('domain', 'results', 'selectorInput'));
    }

    /**
     * Parse DKIM public key record to extract key type and size.
     */
    private function parseDkimPublicKey(string $record): array
    {
        $info = ['type' => 'rsa', 'bits' => null, 'revoked' => false];

        // Parse key type
        if (preg_match('/k\s*=\s*(\w+)/i', $record, $m)) {
            $info['type'] = strtolower($m[1]);
        }

        // Extract public key
        if (preg_match('/p\s*=\s*([A-Za-z0-9+\/=]*)/i', $record, $m)) {
            $keyData = $m[1];

            if (empty($keyData)) {
                $info['revoked'] = true;
                return $info;
            }

            // Try to determine key size
            $derKey = base64_decode($keyData);
            if ($derKey !== false) {
                $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($keyData, 64) . "-----END PUBLIC KEY-----";
                $keyResource = @openssl_pkey_get_public($pem);
                if ($keyResource) {
                    $details = openssl_pkey_get_details($keyResource);
                    if ($details) {
                        $info['bits'] = $details['bits'] ?? null;
                    }
                }
            }
        }

        return $info;
    }

    /**
     * Determine DKIM key status based on key info.
     */
    private function dkimKeyStatus(array $keyInfo): string
    {
        if ($keyInfo['revoked']) return 'revoked';
        if ($keyInfo['bits'] === null) return 'unknown';
        if ($keyInfo['type'] === 'ed25519') return 'strong';
        if ($keyInfo['bits'] >= 2048) return 'strong';
        if ($keyInfo['bits'] >= 1024) return 'ok';
        return 'weak';
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
