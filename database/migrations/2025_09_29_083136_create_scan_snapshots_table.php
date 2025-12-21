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
        Schema::create('scan_snapshots', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->cascadeOnDelete();
            $table->enum('scan_type', ['dns', 'spf', 'blacklist', 'full'])->index();
            // Normalize scan output into booleans/strings for diffing
            $table->boolean('mx_ok')->default(false);
            $table->boolean('spf_ok')->default(false);
            $table->unsignedTinyInteger('spf_lookups')->default(0);
            $table->boolean('dmarc_ok')->default(false);
            $table->boolean('tlsrpt_ok')->default(false);
            $table->boolean('mtasts_ok')->default(false);
            $table->json('rbl_hits')->nullable(); // ["barracuda","spamhaus"]
            $table->unsignedSmallInteger('score')->default(0);
            $table->timestamps();
            
            $table->index(['domain_id', 'scan_type', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_snapshots');
    }
};
