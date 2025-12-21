<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('subscriptions')) {
            Schema::rename('subscriptions', 'app_subscriptions');
        }
    }

    public function down(): void
    {
        if (Schema::hasTable('app_subscriptions')) {
            Schema::rename('app_subscriptions', 'subscriptions');
        }
    }
};
