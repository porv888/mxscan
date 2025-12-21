<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            if (!Schema::hasColumn('users', 'stripe_id')) {
                $table->string('stripe_id')->nullable()->index();
            }
            if (!Schema::hasColumn('users', 'pm_type')) {
                $table->string('pm_type')->nullable();
            }
            if (!Schema::hasColumn('users', 'pm_last_four')) {
                $table->string('pm_last_four', 4)->nullable();
            }
            if (!Schema::hasColumn('users', 'trial_ends_at')) {
                $table->timestamp('trial_ends_at')->nullable();
            }
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            if (Schema::hasColumn('users', 'trial_ends_at')) {
                $table->dropColumn('trial_ends_at');
            }
            if (Schema::hasColumn('users', 'pm_last_four')) {
                $table->dropColumn('pm_last_four');
            }
            if (Schema::hasColumn('users', 'pm_type')) {
                $table->dropColumn('pm_type');
            }
            if (Schema::hasColumn('users', 'stripe_id')) {
                $table->dropColumn('stripe_id');
            }
        });
    }
};
