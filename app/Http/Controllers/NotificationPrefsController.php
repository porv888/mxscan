<?php

namespace App\Http\Controllers;

use App\Models\NotificationPref;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class NotificationPrefsController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware('verified');
    }

    /**
     * Show notification preferences
     */
    public function show()
    {
        $prefs = Auth::user()->getNotificationPrefs();
        
        return view('settings.notifications', compact('prefs'));
    }

    /**
     * Update notification preferences
     */
    public function update(Request $request)
    {
        $request->validate([
            'email_enabled' => 'boolean',
            'slack_enabled' => 'boolean',
            'slack_webhook' => 'nullable|url',
            'weekly_reports' => 'boolean',
        ]);

        $user = Auth::user();
        $prefs = $user->getNotificationPrefs();

        // Check plan restrictions for Slack notifications
        if ($request->boolean('slack_enabled') && !$user->canUseSlackNotifications()) {
            return back()->withErrors([
                'slack_enabled' => 'Slack notifications are only available for Premium and Ultra plans.'
            ]);
        }

        // Check plan restrictions for weekly reports
        if ($request->boolean('weekly_reports') && !$user->canUseWeeklyReports()) {
            return back()->withErrors([
                'weekly_reports' => 'Weekly reports are only available for Premium and Ultra plans.'
            ]);
        }

        $prefs->update([
            'email_enabled' => $request->boolean('email_enabled', true),
            'slack_enabled' => $request->boolean('slack_enabled', false),
            'slack_webhook' => $request->input('slack_webhook'),
            'weekly_reports' => $request->boolean('weekly_reports', true),
        ]);

        return back()->with('success', 'Notification preferences updated successfully.');
    }
}
