<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\Plan;

class PlanSeeder extends Seeder
{
    public function run(): void
    {
        $plans = [
            [
                'name' => 'Freemium',
                'price' => 0.00,
                'currency' => 'EUR',
                'interval' => 'monthly',
                'scan_limit' => 10,
                'domain_limit' => 3,
                'active' => true,
            ],
            [
                'name' => 'Premium',
                'price' => 19.00,
                'currency' => 'EUR',
                'interval' => 'monthly',
                'scan_limit' => 100,
                'domain_limit' => 10,
                'active' => true,
            ],
            [
                'name' => 'Ultra',
                'price' => 49.00,
                'currency' => 'EUR',
                'interval' => 'monthly',
                'scan_limit' => 500,
                'domain_limit' => 50,
                'active' => true,
            ],
        ];

        foreach ($plans as $planData) {
            Plan::updateOrCreate(
                ['name' => $planData['name']],
                $planData
            );
        }
    }
}
