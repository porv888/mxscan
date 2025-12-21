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
        Schema::create('subscriptions', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->onDelete('cascade');
            $table->foreignId('plan_id')->constrained()->onDelete('restrict');
            $table->enum('status', ['active', 'trial', 'canceled', 'expired'])->default('trial');
            $table->datetime('started_at');
            $table->datetime('expires_at')->nullable();
            $table->datetime('canceled_at')->nullable();
            $table->integer('scans_used')->default(0)->comment('Scans used this period');
            $table->datetime('usage_reset_at')->nullable()->comment('When usage counter resets');
            $table->timestamps();
            
            // Indexes
            $table->index('user_id');
            $table->index('plan_id');
            $table->index('status');
            $table->index('expires_at');
            $table->index(['user_id', 'status']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('subscriptions');
    }
};