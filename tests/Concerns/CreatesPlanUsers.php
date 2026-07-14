<?php

namespace Tests\Concerns;

use App\Models\Plan;
use App\Models\Subscription;
use App\Models\User;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;

trait CreatesPlanUsers
{
    protected function setUpPlanTables(): void
    {
        if (!Schema::hasTable('plans')) {
            Schema::create('plans', function (Blueprint $table) {
                $table->id();
                $table->string('name');
                $table->decimal('price', 8, 2)->default(0);
                $table->string('currency')->default('EUR');
                $table->string('interval')->default('monthly');
                $table->integer('scan_limit')->nullable();
                $table->integer('domain_limit')->default(1);
                $table->boolean('active')->default(true);
                $table->timestamps();
            });
        }

        if (!Schema::hasTable('app_subscriptions')) {
            Schema::create('app_subscriptions', function (Blueprint $table) {
                $table->id();
                $table->unsignedBigInteger('user_id');
                $table->unsignedBigInteger('plan_id')->nullable();
                $table->string('status')->default('active');
                $table->timestamp('started_at')->nullable();
                $table->timestamp('renews_at')->nullable();
                $table->timestamp('canceled_at')->nullable();
                $table->timestamps();
            });
        } elseif (!Schema::hasColumn('app_subscriptions', 'plan_id')) {
            Schema::table('app_subscriptions', function (Blueprint $table) {
                $table->unsignedBigInteger('plan_id')->nullable();
                $table->string('status')->default('active');
                $table->timestamp('started_at')->nullable();
                $table->timestamp('renews_at')->nullable();
                $table->timestamp('canceled_at')->nullable();
            });
        }

        Plan::updateOrCreate(['name' => 'Freemium'], [
            'price' => 0,
            'domain_limit' => 1,
            'active' => true,
        ]);
        Plan::updateOrCreate(['name' => 'Premium'], [
            'price' => 19,
            'domain_limit' => 10,
            'active' => true,
        ]);
        Plan::updateOrCreate(['name' => 'Ultra'], [
            'price' => 49,
            'domain_limit' => 50,
            'active' => true,
        ]);
    }

    protected function createPremiumUser(): User
    {
        $this->setUpPlanTables();
        $user = User::factory()->create();
        $plan = Plan::where('name', 'Premium')->first();

        Subscription::create([
            'user_id' => $user->id,
            'plan_id' => $plan->id,
            'status' => 'active',
            'started_at' => now(),
            'renews_at' => now()->addMonth(),
        ]);

        return $user;
    }
}
