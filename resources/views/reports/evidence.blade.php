<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MXScan Evidence Pack - {{ $domain->domain }}</title>
    <style>
        body {
            font-family: 'DejaVu Sans', sans-serif;
            font-size: 12px;
            line-height: 1.4;
            color: #333;
            margin: 0;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 20px;
        }
        
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #1f2937;
            margin-bottom: 10px;
        }
        
        .subtitle {
            color: #6b7280;
            font-size: 14px;
        }
        
        .section {
            margin-bottom: 25px;
        }
        
        .section-title {
            font-size: 16px;
            font-weight: bold;
            color: #1f2937;
            margin-bottom: 10px;
            border-bottom: 1px solid #e5e7eb;
            padding-bottom: 5px;
        }
        
        .info-grid {
            display: table;
            width: 100%;
            margin-bottom: 15px;
        }
        
        .info-row {
            display: table-row;
        }
        
        .info-label {
            display: table-cell;
            font-weight: bold;
            width: 150px;
            padding: 5px 10px 5px 0;
            vertical-align: top;
        }
        
        .info-value {
            display: table-cell;
            padding: 5px 0;
            vertical-align: top;
        }
        
        .status-clean {
            color: #059669;
            font-weight: bold;
        }
        
        .status-listed {
            color: #dc2626;
            font-weight: bold;
        }
        
        .status-warning {
            color: #d97706;
            font-weight: bold;
        }
        
        .dns-record {
            background-color: #f9fafb;
            padding: 8px;
            margin: 5px 0;
            border-left: 3px solid #e5e7eb;
            font-family: monospace;
            font-size: 11px;
        }
        
        .blacklist-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }
        
        .blacklist-table th,
        .blacklist-table td {
            border: 1px solid #e5e7eb;
            padding: 8px;
            text-align: left;
        }
        
        .blacklist-table th {
            background-color: #f9fafb;
            font-weight: bold;
        }
        
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 10px;
        }
        
        .remediation-section {
            background-color: #f0f9ff;
            padding: 15px;
            border-left: 4px solid #0ea5e9;
            margin: 15px 0;
        }
        
        .remediation-title {
            font-weight: bold;
            color: #0c4a6e;
            margin-bottom: 10px;
        }
        
        .remediation-list {
            margin: 0;
            padding-left: 20px;
        }
        
        .remediation-list li {
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="logo">MXScan</div>
        <div class="subtitle">Email Security Evidence Pack</div>
    </div>

    <div class="section">
        <div class="section-title">Domain Information</div>
        <div class="info-grid">
            <div class="info-row">
                <div class="info-label">Domain:</div>
                <div class="info-value">{{ $domain->domain }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Owner:</div>
                <div class="info-value">{{ $domain->user->name }} ({{ $domain->user->email }})</div>
            </div>
            <div class="info-row">
                <div class="info-label">Report Generated:</div>
                <div class="info-value">{{ $generatedAt->format('F j, Y \a\t g:i A T') }}</div>
            </div>
            @if($scan)
            <div class="info-row">
                <div class="info-label">Last Scan:</div>
                <div class="info-value">{{ $scan->created_at->format('F j, Y \a\t g:i A T') }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Security Score:</div>
                <div class="info-value">
                    @if($scan->score >= 80)
                        <span class="status-clean">{{ $scan->score }}/100</span>
                    @elseif($scan->score >= 60)
                        <span class="status-warning">{{ $scan->score }}/100</span>
                    @else
                        <span class="status-listed">{{ $scan->score }}/100</span>
                    @endif
                </div>
            </div>
            @endif
        </div>
    </div>

    @if($scan && $scan->result_json)
        @php
            $results = is_string($scan->result_json) ? json_decode($scan->result_json, true) : $scan->result_json;
        @endphp
        
        <div class="section">
            <div class="section-title">DNS Configuration</div>
            
            @if(isset($results['dns']['records']['mx']) && count($results['dns']['records']['mx']) > 0)
                <div style="margin-bottom: 15px;">
                    <strong>MX Records:</strong>
                    @foreach($results['dns']['records']['mx'] as $mx)
                        <div class="dns-record">{{ $mx['priority'] }} {{ $mx['target'] }}</div>
                    @endforeach
                </div>
            @endif

            @if(isset($results['dns']['records']['spf']) && count($results['dns']['records']['spf']) > 0)
                <div style="margin-bottom: 15px;">
                    <strong>SPF Record:</strong>
                    @foreach($results['dns']['records']['spf'] as $spf)
                        <div class="dns-record">{{ $spf }}</div>
                    @endforeach
                </div>
            @endif

            @if(isset($results['dns']['records']['dmarc']) && count($results['dns']['records']['dmarc']) > 0)
                <div style="margin-bottom: 15px;">
                    <strong>DMARC Record:</strong>
                    @foreach($results['dns']['records']['dmarc'] as $dmarc)
                        <div class="dns-record">{{ $dmarc }}</div>
                    @endforeach
                </div>
            @endif
        </div>
    @endif

    @if($spfCheck)
        <div class="section">
            <div class="section-title">SPF Analysis</div>
            <div class="info-grid">
                <div class="info-row">
                    <div class="info-label">Current SPF Record:</div>
                    <div class="info-value">
                        @if($spfCheck->looked_up_record)
                            <div class="dns-record">{{ $spfCheck->looked_up_record }}</div>
                        @else
                            <span class="status-listed">No SPF record found</span>
                        @endif
                    </div>
                </div>
                <div class="info-row">
                    <div class="info-label">DNS Lookups Used:</div>
                    <div class="info-value">
                        @if($spfCheck->lookup_count >= 9)
                            <span class="status-listed">{{ $spfCheck->lookup_count }}/10 (Critical)</span>
                        @elseif($spfCheck->lookup_count >= 7)
                            <span class="status-warning">{{ $spfCheck->lookup_count }}/10 (Warning)</span>
                        @else
                            <span class="status-clean">{{ $spfCheck->lookup_count }}/10 (Good)</span>
                        @endif
                    </div>
                </div>
                @if($spfCheck->flattened_suggestion)
                    <div class="info-row">
                        <div class="info-label">Flattened SPF:</div>
                        <div class="info-value">
                            <div class="dns-record">{{ $spfCheck->flattened_suggestion }}</div>
                        </div>
                    </div>
                @endif
            </div>
        </div>
    @endif

    <div class="section">
        <div class="section-title">Blacklist Status</div>
        
        @if(count($blacklistResults) > 0)
            <table class="blacklist-table">
                <thead>
                    <tr>
                        <th>RBL Provider</th>
                        <th>Status</th>
                        <th>IP Address</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
                    @foreach($blacklistResults as $result)
                        @php
                            $provider = $rblProviders[$result->provider] ?? ['name' => $result->provider];
                        @endphp
                        <tr>
                            <td>{{ $provider['name'] }}</td>
                            <td>
                                @if($result->is_listed)
                                    <span class="status-listed">LISTED</span>
                                @else
                                    <span class="status-clean">CLEAN</span>
                                @endif
                            </td>
                            <td>{{ $result->ip_address }}</td>
                            <td>{{ $result->details ?? 'N/A' }}</td>
                        </tr>
                    @endforeach
                </tbody>
            </table>
        @else
            <p><span class="status-clean">No blacklist results available or domain is clean on all checked RBLs.</span></p>
        @endif
    </div>

    <div class="remediation-section">
        <div class="remediation-title">Remediation Actions Taken</div>
        <ul class="remediation-list">
            <li>SPF and DMARC records have been properly configured and validated</li>
            <li>All mail server configurations have been reviewed and hardened</li>
            <li>Open mail relay vulnerabilities have been identified and resolved</li>
            <li>Mail server security policies have been implemented and enforced</li>
            <li>Regular monitoring and scanning procedures are in place</li>
            <li>All compromised systems have been cleaned and secured</li>
            <li>Email authentication mechanisms are properly configured</li>
            <li>No unauthorized spam activity has occurred since remediation</li>
        </ul>
    </div>

    <div class="section">
        <div class="section-title">Technical Contact Information</div>
        <div class="info-grid">
            <div class="info-row">
                <div class="info-label">Primary Contact:</div>
                <div class="info-value">{{ $domain->user->name }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Email:</div>
                <div class="info-value">{{ $domain->user->email }}</div>
            </div>
            <div class="info-row">
                <div class="info-label">Domain Registration:</div>
                <div class="info-value">{{ $domain->created_at->format('F j, Y') }}</div>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>This evidence pack was generated by MXScan (app.mxscan.me) on {{ $generatedAt->format('F j, Y \a\t g:i A T') }}</p>
        <p>MXScan provides comprehensive email security monitoring and blacklist management services.</p>
    </div>
</body>
</html>
