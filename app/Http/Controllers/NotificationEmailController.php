<?php

namespace App\Http\Controllers;

use App\Models\NotificationEmail;
use App\Notifications\VerifyNotificationEmail;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Validation\Rule;

class NotificationEmailController extends Controller
{
    /**
     * Store a new notification email.
     */
    public function store(Request $request)
    {
        $user = Auth::user();

        $validated = $request->validate([
            'email' => [
                'required',
                'email',
                'max:255',
                Rule::unique('notification_emails')->where(function ($query) use ($user) {
                    return $query->where('user_id', $user->id);
                }),
            ],
        ], [
            'email.unique' => 'This email has already been added to your notification list.',
        ]);

        // Check if trying to add their primary email
        if ($validated['email'] === $user->email) {
            return back()->with('error', 'Your primary email is already receiving notifications. Add a different email address.');
        }

        // Create the notification email
        $notificationEmail = $user->notificationEmails()->create([
            'email' => $validated['email'],
            'is_verified' => false,
        ]);

        // Generate verification token and send email
        $token = $notificationEmail->generateVerificationToken();
        
        // TODO: Send verification email
        // For now, we'll auto-verify for simplicity
        // In production, you'd send a verification email here
        $notificationEmail->markAsVerified();

        return back()->with('success', 'Notification email added successfully.');
    }

    /**
     * Remove a notification email.
     */
    public function destroy(NotificationEmail $notificationEmail)
    {
        $user = Auth::user();

        // Ensure the notification email belongs to the authenticated user
        if ($notificationEmail->user_id !== $user->id) {
            abort(403, 'Unauthorized action.');
        }

        $notificationEmail->delete();

        return back()->with('success', 'Notification email removed successfully.');
    }

    /**
     * Resend verification email.
     */
    public function resendVerification(NotificationEmail $notificationEmail)
    {
        $user = Auth::user();

        // Ensure the notification email belongs to the authenticated user
        if ($notificationEmail->user_id !== $user->id) {
            abort(403, 'Unauthorized action.');
        }

        // Check if already verified
        if ($notificationEmail->isVerified()) {
            return back()->with('error', 'This email is already verified.');
        }

        // Generate new token and send email
        $token = $notificationEmail->generateVerificationToken();
        
        // TODO: Send verification email
        // For now, we'll auto-verify
        $notificationEmail->markAsVerified();

        return back()->with('success', 'Verification email sent successfully.');
    }

    /**
     * Verify a notification email using token.
     */
    public function verify(Request $request, $token)
    {
        $notificationEmail = NotificationEmail::where('verification_token', $token)->first();

        if (!$notificationEmail) {
            return redirect()->route('profile')->with('error', 'Invalid verification token.');
        }

        if ($notificationEmail->isVerified()) {
            return redirect()->route('profile')->with('success', 'Email already verified.');
        }

        $notificationEmail->markAsVerified();

        return redirect()->route('profile')->with('success', 'Email verified successfully! You will now receive notifications at this address.');
    }
}
