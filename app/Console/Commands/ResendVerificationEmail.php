<?php

namespace App\Console\Commands;

use App\Models\User;
use Illuminate\Console\Command;

class ResendVerificationEmail extends Command
{
    protected $signature = 'email:resend-verification {email}';
    protected $description = 'Resend verification email to a user';

    public function handle()
    {
        $email = $this->argument('email');
        $user = User::where('email', $email)->first();

        if (!$user) {
            $this->error("User with email {$email} not found.");
            return 1;
        }

        if ($user->hasVerifiedEmail()) {
            $this->info("User {$email} is already verified.");
            return 0;
        }

        try {
            $user->sendEmailVerificationNotification();
            $this->info("Verification email sent successfully to {$email}");
            return 0;
        } catch (\Exception $e) {
            $this->error("Failed to send email: " . $e->getMessage());
            return 1;
        }
    }
}
