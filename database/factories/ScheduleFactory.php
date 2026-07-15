<?php

namespace Database\Factories;

use App\Models\Domain;
use App\Models\User;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends \Illuminate\Database\Eloquent\Factories\Factory<\App\Models\Schedule>
 */
class ScheduleFactory extends Factory
{
    public function definition(): array
    {
        return [
            'domain_id' => Domain::factory(),
            'user_id' => User::factory(),
            'scan_type' => 'dns_security',
            'frequency' => 'weekly',
            'cron_expression' => null,
            'next_run_at' => now()->addDay(),
            'last_run_at' => null,
            'status' => 'active',
            'settings' => null,
        ];
    }
}
