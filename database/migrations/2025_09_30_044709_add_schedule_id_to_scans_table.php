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
        Schema::table('scans', function (Blueprint $table) {
            if (!Schema::hasColumn('scans', 'schedule_id')) {
                $table->foreignId('schedule_id')->nullable()->after('user_id')->constrained('schedules')->nullOnDelete();
            }
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            if (Schema::hasColumn('scans', 'schedule_id')) {
                $table->dropForeign(['schedule_id']);
                $table->dropColumn('schedule_id');
            }
        });
    }
};
