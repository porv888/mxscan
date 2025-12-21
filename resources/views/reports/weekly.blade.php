<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>MXScan Weekly Report - {{ $domain->domain }}</title>
    <style>
        body {
            font-family: 'DejaVu Sans', sans-serif;
            font-size: 12px;
            line-height: 1.4;
            color: #374151;
            margin: 0;
            padding: 20px;
        }
        .header {
            text-align: center;
            border-bottom: 2px solid #3b82f6;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #1e293b;
            font-size: 24px;
            margin: 0;
        }
        .header .subtitle {
            color: #64748b;
            font-size: 14px;
            margin: 5px 0;
        }
        .section {
            margin-bottom: 25px;
            page-break-inside: avoid;
        }
        .section h2 {
            color: #1e293b;
            font-size: 16px;
            border-bottom: 1px solid #e2e8f0;
            padding-bottom: 5px;
            margin-bottom: 15px;
        }
        .stats-grid {
            display: table;
            width: 100%;
            margin-bottom: 20px;
        }
        .stat-item {
            display: table-cell;
            text-align: center;
            padding: 15px;
            border: 1px solid #e2e8f0;
            background: #f8fafc;
        }
        .stat-value {
            font-size: 20px;
            font-weight: bold;
            color: #1e293b;
        }
        .stat-label {
            font-size: 10px;
            color: #64748b;
            text-transform: uppercase;
        }
        .incident-item {
            padding: 10px;
            margin-bottom: 10px;
            border-left: 4px solid #e2e8f0;
            background: #f9fafb;
        }
        .incident-critical {
            border-left-color: #dc2626;
        }
        .incident-warning {
            border-left-color: #f59e0b;
        }
        .incident-info {
            border-left-color: #3b82f6;
        }
        .change-item {
            padding: 8px;
            margin-bottom: 8px;
            background: #f0f9ff;
            border-radius: 4px;
        }
        .trend-up {
            color: #059669;
        }
        .trend-down {
            color: #dc2626;
        }
        .trend-stable {
            color: #64748b;
        }
        .footer {
            position: fixed;
            bottom: 20px;
            left: 20px;
            right: 20px;
            text-align: center;
            font-size: 10px;
            color: #9ca3af;
            border-top: 1px solid #e5e7eb;
            padding-top: 10px;
        }
        .page-break {
            page-break-before: always;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>MXScan Weekly Report</h1>
        <div class="subtitle">{{ $domain->domain }}</div>
        <div class="subtitle">{{ $weekStart->format('M j, Y') }} - {{ $weekEnd->format('M j, Y') }}</div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>📊 Executive Summary</h2>
        <div class="stats-grid">
            <div class="stat-item">
                <div class="stat-value">{{ $reportData['stats']['scans_performed'] }}</div>
                <div class="stat-label">Scans Performed</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{ $reportData['stats']['average_score'] }}/100</div>
                <div class="stat-label">Average Score</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">{{ $reportData['stats']['incidents_raised'] }}</div>
                <div class="stat-label">Incidents</div>
            </div>
            <div class="stat-item">
                <div class="stat-value 
                    @if($reportData['stats']['score_trend'] === 'improving') trend-up
                    @elseif($reportData['stats']['score_trend'] === 'declining') trend-down
                    @else trend-stable @endif">
                    @if($reportData['stats']['score_trend'] === 'improving') ↗
                    @elseif($reportData['stats']['score_trend'] === 'declining') ↘
                    @else → @endif
                </div>
                <div class="stat-label">Score Trend</div>
            </div>
        </div>

        <p><strong>Weekly Overview:</strong> 
        @if($reportData['stats']['scans_performed'] > 0)
            Your domain was scanned {{ $reportData['stats']['scans_performed'] }} time{{ $reportData['stats']['scans_performed'] > 1 ? 's' : '' }} this week
            with an average security score of {{ $reportData['stats']['average_score'] }}/100.
        @else
            No scans were performed this week.
        @endif

        @if($reportData['stats']['incidents_raised'] > 0)
            {{ $reportData['stats']['incidents_raised'] }} incident{{ $reportData['stats']['incidents_raised'] > 1 ? 's were' : ' was' }} detected
            @if($reportData['stats']['critical_incidents'] > 0)
                ({{ $reportData['stats']['critical_incidents'] }} critical).
            @else
                .
            @endif
        @else
            No incidents were detected.
        @endif
        </p>
    </div>

    @if($reportData['incidents']->isNotEmpty())
    <!-- Incidents -->
    <div class="section">
        <h2>🚨 Security Incidents</h2>
        @foreach($reportData['incidents'] as $incident)
        <div class="incident-item incident-{{ $incident->severity }}">
            <strong>{{ ucfirst($incident->severity) }}:</strong> {{ $incident->message }}
            <br><small>{{ $incident->created_at->format('M j, Y g:i A') }}</small>
        </div>
        @endforeach
    </div>
    @endif

    @if($reportData['deltas']->isNotEmpty())
    <!-- Changes Detected -->
    <div class="section">
        <h2>🔄 Changes Detected</h2>
        @foreach($reportData['deltas'] as $delta)
        <div class="change-item">
            <strong>{{ $delta->created_at->format('M j, g:i A') }}:</strong> {{ $delta->getSummary() }}
        </div>
        @endforeach
    </div>
    @endif

    @if($reportData['stats']['rbl_listings'] > 0 || $reportData['stats']['rbl_delistings'] > 0)
    <!-- Blacklist Activity -->
    <div class="section">
        <h2>🛡️ Blacklist Monitoring</h2>
        @if($reportData['stats']['rbl_listings'] > 0)
        <p><strong>⚠️ New Listings:</strong> {{ $reportData['stats']['rbl_listings'] }} blacklist listing{{ $reportData['stats']['rbl_listings'] > 1 ? 's' : '' }} detected this week.</p>
        @endif
        
        @if($reportData['stats']['rbl_delistings'] > 0)
        <p><strong>✅ Delistings:</strong> {{ $reportData['stats']['rbl_delistings'] }} blacklist delisting{{ $reportData['stats']['rbl_delistings'] > 1 ? 's' : '' }} this week.</p>
        @endif
        
        @if($reportData['stats']['rbl_listings'] === 0 && $reportData['stats']['rbl_delistings'] === 0)
        <p><strong>✅ Clean Status:</strong> No blacklist changes detected this week.</p>
        @endif
    </div>
    @endif

    <!-- Recommendations -->
    <div class="section">
        <h2>💡 Recommendations</h2>
        @if($reportData['stats']['critical_incidents'] > 0)
        <p><strong>🚨 Immediate Action Required:</strong> You have {{ $reportData['stats']['critical_incidents'] }} critical incident{{ $reportData['stats']['critical_incidents'] > 1 ? 's' : '' }} that need immediate attention.</p>
        @endif

        @if($reportData['stats']['average_score'] < 70)
        <p><strong>📈 Improve Security Score:</strong> Your average score is {{ $reportData['stats']['average_score'] }}/100. Consider implementing missing DNS records and security policies.</p>
        @endif

        @if($reportData['stats']['score_trend'] === 'declining')
        <p><strong>📉 Score Declining:</strong> Your security score is trending downward. Review recent changes and incidents.</p>
        @endif

        @if($reportData['stats']['scans_performed'] === 0)
        <p><strong>🔍 Regular Monitoring:</strong> No scans were performed this week. Consider enabling automated scanning for continuous monitoring.</p>
        @endif

        @if($reportData['stats']['incidents_raised'] === 0 && $reportData['stats']['average_score'] >= 80)
        <p><strong>🎉 Great Job:</strong> Your domain security is performing well with no incidents and a strong security score!</p>
        @endif
    </div>

    <!-- Next Steps -->
    <div class="section">
        <h2>🎯 Next Steps</h2>
        <ol>
            <li>Review and address any critical incidents immediately</li>
            <li>Monitor your domain dashboard regularly at app.mxscan.me</li>
            <li>Implement recommended security improvements</li>
            <li>Keep DNS records and security policies up to date</li>
            <li>Consider upgrading your plan for enhanced monitoring features</li>
        </ol>
    </div>

    <div class="footer">
        Generated by MXScan on {{ now()->format('M j, Y \a\t g:i A') }} | Visit app.mxscan.me for real-time monitoring
    </div>
</body>
</html>
