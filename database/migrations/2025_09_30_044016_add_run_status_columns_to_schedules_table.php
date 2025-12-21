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
        Schema::table('schedules', function (Blueprint $table) {
            if (!Schema::hasColumn('schedules', 'is_running')) {
                $table->boolean('is_running')->default(false)->after('last_run_at');
            }
            if (!Schema::hasColumn('schedules', 'last_run_status')) {
                $table->string('last_run_status', 20)->nullable()->after('is_running')->comment('ok|failed|warning');
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('schedules', function (Blueprint $table) {
            if (Schema::hasColumn('schedules', 'is_running')) {
                $table->dropColumn('is_running');
            }
            if (Schema::hasColumn('schedules', 'last_run_status')) {
                $table->dropColumn('last_run_status');
            }
        });
    }
};
