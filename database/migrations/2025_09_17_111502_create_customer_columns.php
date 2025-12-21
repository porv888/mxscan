<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            if (! Schema::hasColumn('users', 'stripe_id')) {
                $table->string('stripe_id')->nullable()->index();
            }
            if (! Schema::hasColumn('users', 'pm_type')) {
                $table->string('pm_type')->nullable();
            }
            if (! Schema::hasColumn('users', 'pm_last_four')) {
                $table->string('pm_last_four', 4)->nullable();
            }
            if (! Schema::hasColumn('users', 'trial_ends_at')) {
                $table->timestamp('trial_ends_at')->nullable();
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            if (Schema::hasColumn('users', 'stripe_id')) {
                // Drop index then column if they exist
                try {
                    $table->dropIndex(['stripe_id']);
                } catch (\Throwable $e) {
                    // ignore if index naming differs
                }
            }

            $columns = ['stripe_id','pm_type','pm_last_four','trial_ends_at'];
            foreach ($columns as $col) {
                if (Schema::hasColumn('users', $col)) {
                    $table->dropColumn($col);
                }
            }
        });
    }
};
