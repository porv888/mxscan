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
            // Change raw_headers from JSON to LONGTEXT
            $table->longText('raw_headers')->nullable()->change();
            
            // Add raw_body field
            $table->longText('raw_body')->nullable()->after('raw_headers');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('delivery_checks', function (Blueprint $table) {
            // Revert raw_headers back to JSON
            $table->json('raw_headers')->nullable()->change();
            
            // Drop raw_body
            $table->dropColumn('raw_body');
        });
    }
};
