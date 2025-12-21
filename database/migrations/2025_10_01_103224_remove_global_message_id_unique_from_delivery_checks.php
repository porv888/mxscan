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
        Schema::table('delivery_checks', function (Blueprint $table) {
            // Remove the old global unique constraint on message_id
            // Keep the composite unique constraint (delivery_monitor_id, message_id)
            $table->dropUnique('uniq_message_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('delivery_checks', function (Blueprint $table) {
            //
        });
    }
};
