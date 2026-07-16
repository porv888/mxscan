<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('domain_senders', function (Blueprint $table) {
            $table->id();
            $table->foreignId('domain_id')->constrained()->cascadeOnDelete();
            $table->string('sender_type', 40);
            $table->string('provider', 80)->nullable();
            $table->string('mechanism', 20);
            $table->string('value', 512);
            $table->string('source', 20);
            $table->string('confidence', 20)->default('unknown');
            $table->string('confirmation_status', 20)->default('pending');
            $table->foreignId('confirmed_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('confirmed_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->boolean('is_active')->default(true);
            $table->char('fingerprint', 64);
            $table->timestamps();

            $table->unique(['domain_id', 'fingerprint']);
            $table->index(['domain_id', 'is_active']);
            $table->index(['domain_id', 'confirmation_status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('domain_senders');
    }
};
