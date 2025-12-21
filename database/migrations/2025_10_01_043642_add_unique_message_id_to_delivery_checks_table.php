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
            // Add unique index on message_id to prevent duplicate processing
            // Note: message_id can be null, so we use a unique index that allows nulls
            $table->unique('message_id', 'uniq_message_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('delivery_checks', function (Blueprint $table) {
            $table->dropUnique('uniq_message_id');
        });
    }
};
