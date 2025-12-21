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
            // Change tti_ms from integer to bigInteger (unsigned)
            $table->unsignedBigInteger('tti_ms')->nullable()->change();
            
            // Ensure mx_ip can handle IPv6 (45 chars max)
            $table->string('mx_ip', 45)->nullable()->change();
            
            // Ensure mx_host is properly sized
            $table->string('mx_host', 191)->nullable()->change();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('delivery_checks', function (Blueprint $table) {
            // Revert to integer
            $table->integer('tti_ms')->nullable()->change();
            
            // Revert to original sizes
            $table->string('mx_ip', 64)->nullable()->change();
            $table->string('mx_host', 255)->nullable()->change();
        });
    }
};
