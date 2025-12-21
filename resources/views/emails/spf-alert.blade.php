<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SPF Alert - {{ $domain->domain }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            background: #1f2937;
            color: white;
            padding: 20px;
            border-radius: 8px 8px 0 0;
            text-align: center;
        }
        .content {
            background: #f9fafb;
            padding: 30px;
            border-radius: 0 0 8px 8px;
        }
        .alert-box {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
        }
        .code-block {
            background: #1f2937;
            color: #e5e7eb;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
            overflow-x: auto;
            margin: 10px 0;
        }
        .button {
            display: inline-block;
            background: #3b82f6;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            margin: 20px 0;
        }
        .stats {
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
        }
        .footer {
            text-align: center;
            color: #6b7280;
            font-size: 14px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1 style="margin: 0;">🛡️ SPF Alert</h1>
        <p style="margin: 10px 0 0 0;">{{ $domain->domain }}</p>
    </div>

    <div class="content">
        <h2>SPF Attention Required</h2>
        
        <p>Hello,</p>
        
        <p>Our automated SPF monitoring has detected an issue with your domain <strong>{{ $domain->domain }}</strong> that requires your attention.</p>

        <div class="alert-box">
            <strong>Alert Reasons:</strong>
            <ul style="margin: 10px 0;">
                @foreach($alertReasons as $reason)
                    <li>{{ $reason }}</li>
                @endforeach
            </ul>
        </div>

        <div class="stats">
            <h3 style="margin-top: 0;">Current SPF Status</h3>
            <p><strong>DNS Lookups Used:</strong> {{ $currentCheck->lookup_count }}/10</p>
            <p><strong>Last Checked:</strong> {{ $currentCheck->created_at->format('M j, Y H:i T') }}</p>
            
            @if($currentCheck->looked_up_record)
                <p><strong>Current SPF Record:</strong></p>
                <div class="code-block">{{ $currentCheck->looked_up_record }}</div>
            @else
                <p><strong>SPF Status:</strong> No SPF record found</p>
            @endif

            @if(!empty($currentCheck->warnings))
                <p><strong>Warnings:</strong></p>
                <ul>
                    @foreach($currentCheck->warnings as $warning)
                        <li>{{ $warning }}</li>
                    @endforeach
                </ul>
            @endif
        </div>

        @if($previousCheck && $previousCheck->looked_up_record !== $currentCheck->looked_up_record)
            <div class="stats">
                <h3 style="margin-top: 0;">Previous SPF Record</h3>
                @if($previousCheck->looked_up_record)
                    <div class="code-block">{{ $previousCheck->looked_up_record }}</div>
                @else
                    <p><em>No previous SPF record</em></p>
                @endif
            </div>
        @endif

        @if($currentCheck->flattened_suggestion)
            <div class="stats">
                <h3 style="margin-top: 0;">Recommended Flattened SPF</h3>
                <p>To reduce DNS lookups, consider using this flattened version:</p>
                <div class="code-block">{{ $currentCheck->flattened_suggestion }}</div>
                <p style="font-size: 14px; color: #6b7280; margin-top: 10px;">
                    <em>Note: Flattened SPF records may need periodic updates if sender IPs change.</em>
                </p>
            </div>
        @endif

        <div style="text-align: center;">
            <a href="{{ $spfUrl }}" class="button">View Full SPF Analysis</a>
        </div>

        <h3>What should you do?</h3>
        <ul>
            <li><strong>High DNS lookups (≥9):</strong> Consider flattening your SPF record to reduce lookups</li>
            <li><strong>SPF record changed:</strong> Verify the change was intentional and update your documentation</li>
            <li><strong>No SPF record:</strong> Add an SPF record to improve email deliverability</li>
        </ul>

        <p>If you need assistance with SPF optimization, please don't hesitate to contact our support team.</p>

        <p>Best regards,<br>
        The MXScan Team</p>
    </div>

    <div class="footer">
        <p>This is an automated alert from MXScan SPF monitoring.</p>
        <p>You're receiving this because you have SPF monitoring enabled for {{ $domain->domain }}.</p>
    </div>
</body>
</html>
