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
        Schema::create('plans', function (Blueprint $table) {
            $table->id();
            $table->string('name', 100);
            $table->decimal('price', 10, 2);
            $table->string('currency', 10)->default('EUR');
            $table->enum('interval', ['monthly', 'yearly'])->default('monthly');
            $table->integer('scan_limit')->default(50)->comment('Scans per month');
            $table->integer('domain_limit')->default(5)->comment('Max domains allowed');
            $table->boolean('active')->default(true);
            $table->timestamps();
            
            // Indexes
            $table->index('active');
            $table->index(['price', 'interval']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('plans');
    }
};