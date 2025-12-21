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
        Schema::create('scan_deltas', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->cascadeOnDelete();
            $table->foreignId('snapshot_id')->constrained('scan_snapshots')->cascadeOnDelete();
            $table->json('changes'); // [{field:"mx_ok", from:false, to:true}]
            $table->timestamps();
            
            $table->index(['domain_id', 'created_at']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_deltas');
    }
};
