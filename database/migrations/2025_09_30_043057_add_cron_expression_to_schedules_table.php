<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('schedules', function (Blueprint $table) {
            // Add cron_expression column if it doesn't exist
            if (!Schema::hasColumn('schedules', 'cron_expression')) {
                $table->string('cron_expression')->nullable()->after('frequency')->comment('For custom frequency');
            }
        });
        
        // Update frequency enum to include 'custom' option
        DB::statement("ALTER TABLE schedules MODIFY COLUMN frequency ENUM('daily', 'weekly', 'monthly', 'custom') NOT NULL DEFAULT 'weekly'");
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('schedules', function (Blueprint $table) {
            if (Schema::hasColumn('schedules', 'cron_expression')) {
                $table->dropColumn('cron_expression');
            }
        });
        
        // Revert frequency enum back to original values
        DB::statement("ALTER TABLE schedules MODIFY COLUMN frequency ENUM('daily', 'weekly', 'monthly') NOT NULL DEFAULT 'weekly'");
    }
};
