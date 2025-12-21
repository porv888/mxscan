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
        Schema::create('scan_results', function (Blueprint $table) {
            $table->id();
            $table->uuid('scan_id');
            $table->string('phase'); // MX, SPF, DMARC, TLS-RPT, MTA-STS
            $table->enum('status', ['pass', 'fail', 'warn']);
            $table->text('message')->nullable();
            $table->longText('raw_data')->nullable();
            $table->timestamps();
            
            // Foreign key constraint
            $table->foreign('scan_id')->references('id')->on('scans')->onDelete('cascade');
            
            // Add indexes
            $table->index('scan_id');
            $table->index('phase');
            $table->index('status');
            $table->index(['scan_id', 'phase']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_results');
    }
};
