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
        Schema::create('blacklist_results', function (Blueprint $table) {
            $table->id();
            $table->uuid('scan_id');
            $table->string('provider', 100)->comment('RBL provider name (e.g., Spamhaus, Barracuda)');
            $table->string('ip_address', 45)->comment('IP address that was checked');
            $table->enum('status', ['ok', 'listed'])->default('ok');
            $table->text('message')->nullable()->comment('Details from RBL provider');
            $table->string('removal_url')->nullable()->comment('URL to request delisting');
            $table->timestamps();
            
            // Foreign key constraint
            $table->foreign('scan_id')->references('id')->on('scans')->onDelete('cascade');
            
            // Add indexes
            $table->index('scan_id');
            $table->index('provider');
            $table->index('status');
            $table->index('ip_address');
            $table->index(['scan_id', 'provider']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('blacklist_results');
    }
};