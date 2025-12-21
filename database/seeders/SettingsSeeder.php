<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class SettingsSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        $settings = [
            [
                'key_name' => 'app_name',
                'value' => 'Domain Security Scanner',
                'type' => 'string',
                'description' => 'Application name displayed to users',
                'is_public' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'key_name' => 'max_concurrent_scans',
                'value' => '5',
                'type' => 'integer',
                'description' => 'Maximum number of concurrent scans allowed',
                'is_public' => false,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'key_name' => 'scan_timeout_seconds',
                'value' => '30',
                'type' => 'integer',
                'description' => 'Timeout for individual DNS queries in seconds',
                'is_public' => false,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'key_name' => 'trial_duration_days',
                'value' => '14',
                'type' => 'integer',
                'description' => 'Default trial period duration in days',
                'is_public' => false,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'key_name' => 'stripe_public_key',
                'value' => '',
                'type' => 'string',
                'description' => 'Stripe publishable key for payments',
                'is_public' => false,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'key_name' => 'maintenance_mode',
                'value' => 'false',
                'type' => 'boolean',
                'description' => 'Enable maintenance mode',
                'is_public' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'key_name' => 'registration_enabled',
                'value' => 'true',
                'type' => 'boolean',
                'description' => 'Allow new user registrations',
                'is_public' => true,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ];

        DB::table('settings')->insert($settings);
    }
}