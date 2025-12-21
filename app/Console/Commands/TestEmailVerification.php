<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Log;

class TestEmailVerification extends Command
{
    protected $signature = 'test:email-verification {email}';
    protected $description = 'Test email verification system with a real email address';

    public function handle()
    {
        $email = $this->argument('email');
        
        $this->info("Testing email verification system...");
        $this->info("Target email: {$email}");
        
        // Check mail configuration
        $this->info("\nMail Configuration:");
        $this->line("  Mailer: " . config('mail.default'));
        $this->line("  Host: " . config('mail.mailers.smtp.host'));
        $this->line("  Port: " . config('mail.mailers.smtp.port'));
        $this->line("  Encryption: " . config('mail.mailers.smtp.encryption'));
        $this->line("  From: " . config('mail.from.address'));
        
        // Create or find test user
        $user = User::where('email', $email)->first();
        
        if ($user) {
            $this->info("\nFound existing user (ID: {$user->id})");
            if ($user->hasVerifiedEmail()) {
                $this->warn("User is already verified. Resetting verification status...");
                $user->email_verified_at = null;
                $user->save();
            }
        } else {
            $this->info("\nCreating new test user...");
            $user = User::create([
                'name' => 'Test User',
                'email' => $email,
                'password' => bcrypt('password123'),
                'email_verified_at' => null,
            ]);
            $this->info("User created (ID: {$user->id})");
        }
        
        // Send verification email
        $this->info("\nSending verification email...");
        
        try {
            Log::info("Attempting to send verification email", ['email' => $email]);
            $user->sendEmailVerificationNotification();
            $this->info("✓ Verification email sent successfully!");
            $this->line("\nPlease check the inbox for: {$email}");
            $this->line("Also check spam/junk folder if not in inbox.");
            return 0;
        } catch (\Exception $e) {
            $this->error("✗ Failed to send email");
            $this->error("Error: " . $e->getMessage());
            Log::error("Failed to send verification email", [
                'email' => $email,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            return 1;
        }
    }
}
