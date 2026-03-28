<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

class GoogleController extends Controller
{
    /**
     * Redirect the user to Google's OAuth page.
     */
    public function redirect()
    {
        return Socialite::driver('google')->redirect();
    }

    /**
     * Handle the callback from Google.
     */
    public function callback()
    {
        try {
            $googleUser = Socialite::driver('google')->user();
        } catch (\Exception $e) {
            Log::error('Google OAuth callback failed', ['error' => $e->getMessage()]);
            return redirect()->route('login')->with('error', 'Google authentication failed. Please try again.');
        }

        // Check if a user with this Google ID already exists
        $user = User::where('google_id', $googleUser->getId())->first();

        if ($user) {
            // Existing Google user — log them in
            $user->update([
                'google_avatar' => $googleUser->getAvatar(),
            ]);

            Auth::login($user, true);
            Log::info('Google OAuth login', ['user_id' => $user->id, 'email' => $user->email]);

            return redirect()->intended('/dashboard');
        }

        // Check if a user with the same email exists (registered via form)
        $user = User::where('email', $googleUser->getEmail())->first();

        if ($user) {
            // Link Google account to existing user
            $user->update([
                'google_id' => $googleUser->getId(),
                'google_avatar' => $googleUser->getAvatar(),
            ]);

            // Mark email as verified since Google already verified it
            if (!$user->hasVerifiedEmail()) {
                $user->markEmailAsVerified();
            }

            Auth::login($user, true);
            Log::info('Google OAuth linked to existing account', ['user_id' => $user->id, 'email' => $user->email]);

            return redirect()->intended('/dashboard');
        }

        // Create a new user
        $user = User::create([
            'name' => $googleUser->getName(),
            'email' => $googleUser->getEmail(),
            'google_id' => $googleUser->getId(),
            'google_avatar' => $googleUser->getAvatar(),
            'password' => Hash::make(Str::random(24)),
            'email_verified_at' => now(),
        ]);

        // Set session flag for Google Ads conversion tracking
        session(['just_registered' => true]);

        Auth::login($user, true);
        Log::info('Google OAuth new user created', ['user_id' => $user->id, 'email' => $user->email]);

        return redirect()->route('dashboard');
    }
}
