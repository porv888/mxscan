<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Stripe\Webhook;
use Stripe\Exception\SignatureVerificationException;
use App\Models\User;
use App\Models\Plan;
use App\Models\Subscription as AppSubscription;
use Laravel\Cashier\Subscription as CashierSubscription;

class StripeWebhookController extends Controller
{
    /**
     * Handle incoming Stripe webhook events.
     *
     * @param Request $request
     * @return Response
     */
    public function handle(Request $request): Response
    {
        $payload = $request->getContent();
        $sigHeader = $request->header('Stripe-Signature');
        $webhookSecret = config('services.stripe.webhook_secret');

        try {
            // Verify the webhook signature
            $event = Webhook::constructEvent($payload, $sigHeader, $webhookSecret);
            
            // Log the received event
            Log::info('Stripe webhook received', [
                'event_id' => $event->id,
                'event_type' => $event->type,
                'created' => $event->created,
                'livemode' => $event->livemode ?? false
            ]);

            // Handle different event types
            switch ($event->type) {
                case 'customer.subscription.created':
                    $this->handleSubscriptionCreated($event);
                    break;

                case 'customer.subscription.updated':
                    $this->handleSubscriptionUpdated($event);
                    break;

                case 'customer.subscription.deleted':
                    $this->handleSubscriptionDeleted($event);
                    break;

                case 'customer.subscription.trial_will_end':
                    $this->handleSubscriptionTrialWillEnd($event);
                    break;

                case 'invoice.payment_succeeded':
                    $this->handleInvoicePaymentSucceeded($event);
                    break;

                case 'invoice.payment_failed':
                    $this->handleInvoicePaymentFailed($event);
                    break;

                case 'customer.created':
                    $this->handleCustomerCreated($event);
                    break;

                case 'customer.updated':
                    $this->handleCustomerUpdated($event);
                    break;

                case 'payment_method.attached':
                    $this->handlePaymentMethodAttached($event);
                    break;

                default:
                    Log::info('Unhandled Stripe webhook event type', [
                        'event_type' => $event->type,
                        'event_id' => $event->id
                    ]);
                    break;
            }

            return response('ok', 200);

        } catch (SignatureVerificationException $e) {
            Log::error('Stripe webhook signature verification failed', [
                'error' => $e->getMessage(),
                'payload_length' => strlen($payload),
                'signature_header' => $sigHeader ? 'present' : 'missing'
            ]);
            
            return response('Invalid signature', 400);

        } catch (\Exception $e) {
            Log::error('Stripe webhook processing failed', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
            
            return response('Webhook processing failed', 500);
        }
    }

    /**
     * Handle subscription created event.
     */
    private function handleSubscriptionCreated($event): void
    {
        $subscription = $event->data->object;
        
        Log::info('Processing subscription created', [
            'subscription_id' => $subscription->id,
            'customer_id' => $subscription->customer,
            'status' => $subscription->status
        ]);

        try {
            // Find the user by Stripe customer ID
            $user = User::where('stripe_id', $subscription->customer)->first();
            if (!$user) {
                Log::warning('User not found for Stripe customer in subscription created', [
                    'customer_id' => $subscription->customer,
                    'subscription_id' => $subscription->id
                ]);
                return;
            }

            // The Cashier subscription should already be created by this point
            // We just need to ensure our app subscription is in sync
            $this->syncAppSubscriptionFromStripe($user, $subscription);

            Log::info('Successfully processed subscription created', [
                'user_id' => $user->id,
                'subscription_id' => $subscription->id
            ]);

        } catch (\Exception $e) {
            Log::error('Error processing subscription created', [
                'subscription_id' => $subscription->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Handle subscription updated event.
     */
    private function handleSubscriptionUpdated($event): void
    {
        $subscription = $event->data->object;
        
        Log::info('Processing subscription updated', [
            'subscription_id' => $subscription->id,
            'customer_id' => $subscription->customer,
            'status' => $subscription->status
        ]);

        try {
            // Find the user by Stripe customer ID
            $user = User::where('stripe_id', $subscription->customer)->first();
            if (!$user) {
                Log::warning('User not found for Stripe customer in subscription updated', [
                    'customer_id' => $subscription->customer,
                    'subscription_id' => $subscription->id
                ]);
                return;
            }

            // Update Cashier subscription
            $cashierSubscription = $user->subscriptions()->where('stripe_id', $subscription->id)->first();
            if ($cashierSubscription) {
                $cashierSubscription->update([
                    'stripe_status' => $subscription->status,
                    'ends_at' => $subscription->status === 'canceled' && $subscription->current_period_end ? 
                        \Carbon\Carbon::createFromTimestamp($subscription->current_period_end) : null
                ]);
            }

            // Sync app subscription
            $this->syncAppSubscriptionFromStripe($user, $subscription);

            Log::info('Successfully processed subscription updated', [
                'user_id' => $user->id,
                'subscription_id' => $subscription->id
            ]);

        } catch (\Exception $e) {
            Log::error('Error processing subscription updated', [
                'subscription_id' => $subscription->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Handle subscription deleted event.
     */
    private function handleSubscriptionDeleted($event): void
    {
        $subscription = $event->data->object;
        
        Log::info('Processing subscription deleted', [
            'subscription_id' => $subscription->id,
            'customer_id' => $subscription->customer,
            'status' => $subscription->status
        ]);

        try {
            // Find the user by Stripe customer ID
            $user = User::where('stripe_id', $subscription->customer)->first();
            if (!$user) {
                Log::warning('User not found for Stripe customer in subscription deleted', [
                    'customer_id' => $subscription->customer,
                    'subscription_id' => $subscription->id
                ]);
                return;
            }

            // Update Cashier subscription
            $cashierSubscription = $user->subscriptions()->where('stripe_id', $subscription->id)->first();
            if ($cashierSubscription) {
                $cashierSubscription->update([
                    'stripe_status' => 'canceled',
                    'ends_at' => now()
                ]);
            }

            // Cancel app subscription and revert to freemium
            $appSubscription = $user->subscriptions()->where('status', 'active')->first();
            if ($appSubscription) {
                $appSubscription->update([
                    'status' => 'canceled',
                    'canceled_at' => now(),
                ]);
            }

            Log::info('Successfully processed subscription deleted', [
                'user_id' => $user->id,
                'subscription_id' => $subscription->id
            ]);

        } catch (\Exception $e) {
            Log::error('Error processing subscription deleted', [
                'subscription_id' => $subscription->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Handle subscription trial will end event.
     */
    private function handleSubscriptionTrialWillEnd($event): void
    {
        $subscription = $event->data->object;
        
        Log::info('Processing subscription trial will end', [
            'subscription_id' => $subscription->id,
            'customer_id' => $subscription->customer,
            'trial_end' => $subscription->trial_end
        ]);

        // TODO: Implement trial ending logic
        // - Send trial ending notification
        // - Prompt for payment method
    }

    /**
     * Handle invoice payment succeeded event.
     */
    private function handleInvoicePaymentSucceeded($event): void
    {
        $invoice = $event->data->object;
        
        Log::info('Processing invoice payment succeeded', [
            'invoice_id' => $invoice->id,
            'customer_id' => $invoice->customer,
            'amount_paid' => $invoice->amount_paid,
            'subscription_id' => $invoice->subscription
        ]);

        try {
            // Find the user by Stripe customer ID
            $user = User::where('stripe_id', $invoice->customer)->first();
            if (!$user) {
                Log::warning('User not found for Stripe customer', [
                    'customer_id' => $invoice->customer,
                    'invoice_id' => $invoice->id
                ]);
                return;
            }

            // Find or update the Cashier subscription
            if ($invoice->subscription) {
                $cashierSubscription = $user->subscriptions()->where('stripe_id', $invoice->subscription)->first();
                if ($cashierSubscription) {
                    // Update Cashier subscription status to active
                    $cashierSubscription->update([
                        'stripe_status' => 'active',
                        'ends_at' => null // Clear any previous end date
                    ]);
                    
                    Log::info('Updated Cashier subscription status', [
                        'user_id' => $user->id,
                        'subscription_id' => $cashierSubscription->id,
                        'stripe_id' => $invoice->subscription
                    ]);
                }

                // Update or create app subscription
                $this->updateAppSubscription($user, $invoice);
            }

            Log::info('Successfully processed invoice payment', [
                'user_id' => $user->id,
                'invoice_id' => $invoice->id
            ]);

        } catch (\Exception $e) {
            Log::error('Error processing invoice payment succeeded', [
                'invoice_id' => $invoice->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Handle invoice payment failed event.
     */
    private function handleInvoicePaymentFailed($event): void
    {
        $invoice = $event->data->object;
        
        Log::info('Processing invoice payment failed', [
            'invoice_id' => $invoice->id,
            'customer_id' => $invoice->customer,
            'amount_due' => $invoice->amount_due,
            'subscription_id' => $invoice->subscription
        ]);

        // TODO: Implement payment failure logic
        // - Update payment status
        // - Send payment failure notification
        // - Handle dunning management
    }

    /**
     * Handle customer created event.
     */
    private function handleCustomerCreated($event): void
    {
        $customer = $event->data->object;
        
        Log::info('Processing customer created', [
            'customer_id' => $customer->id,
            'email' => $customer->email
        ]);

        // TODO: Implement customer creation logic
        // - Link Stripe customer to user account
        // - Update customer metadata
    }

    /**
     * Handle customer updated event.
     */
    private function handleCustomerUpdated($event): void
    {
        $customer = $event->data->object;
        
        Log::info('Processing customer updated', [
            'customer_id' => $customer->id,
            'email' => $customer->email
        ]);

        // TODO: Implement customer update logic
        // - Sync customer data with user account
        // - Update billing information
    }

    /**
     * Handle payment method attached event.
     */
    private function handlePaymentMethodAttached($event): void
    {
        $paymentMethod = $event->data->object;
        
        Log::info('Processing payment method attached', [
            'payment_method_id' => $paymentMethod->id,
            'customer_id' => $paymentMethod->customer,
            'type' => $paymentMethod->type
        ]);

        // TODO: Implement payment method attachment logic
        // - Update default payment method
        // - Send confirmation notification
    }

    /**
     * Update or create app subscription based on Stripe invoice data.
     */
    private function updateAppSubscription(User $user, $invoice): void
    {
        try {
            // Extract plan information from invoice line items
            $lineItem = $invoice->lines->data[0] ?? null;
            if (!$lineItem) {
                Log::warning('No line items found in invoice', [
                    'invoice_id' => $invoice->id,
                    'user_id' => $user->id
                ]);
                return;
            }

            // Get the Stripe price ID
            $stripePriceId = $lineItem->price->id ?? null;
            if (!$stripePriceId) {
                Log::warning('No price ID found in invoice line item', [
                    'invoice_id' => $invoice->id,
                    'user_id' => $user->id
                ]);
                return;
            }

            // Find the corresponding plan in our database
            // For now, we'll map based on the amount since we don't have stripe_price_id in plans table
            $amount = $lineItem->amount; // Amount in cents
            $plan = $this->findPlanByAmount($amount);

            if (!$plan) {
                Log::warning('No matching plan found for invoice amount', [
                    'invoice_id' => $invoice->id,
                    'amount' => $amount,
                    'stripe_price_id' => $stripePriceId,
                    'user_id' => $user->id
                ]);
                return;
            }

            // Calculate subscription period
            $periodStart = \Carbon\Carbon::createFromTimestamp($lineItem->period->start);
            $periodEnd = \Carbon\Carbon::createFromTimestamp($lineItem->period->end);

            // Update or create app subscription
            $appSubscription = $user->subscriptions()->where('status', 'active')->first();
            
            if ($appSubscription) {
                // Update existing subscription
                $appSubscription->update([
                    'plan_id' => $plan->id,
                    'status' => 'active',
                    'expires_at' => $periodEnd,
                    'renews_at' => $periodEnd,
                    'canceled_at' => null,
                ]);
                
                Log::info('Updated existing app subscription', [
                    'subscription_id' => $appSubscription->id,
                    'plan_id' => $plan->id,
                    'user_id' => $user->id
                ]);
            } else {
                // Create new subscription
                $appSubscription = AppSubscription::create([
                    'user_id' => $user->id,
                    'plan_id' => $plan->id,
                    'status' => 'active',
                    'started_at' => $periodStart,
                    'expires_at' => $periodEnd,
                    'renews_at' => $periodEnd,
                ]);
                
                Log::info('Created new app subscription', [
                    'subscription_id' => $appSubscription->id,
                    'plan_id' => $plan->id,
                    'user_id' => $user->id
                ]);
            }

        } catch (\Exception $e) {
            Log::error('Error updating app subscription', [
                'user_id' => $user->id,
                'invoice_id' => $invoice->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Find plan by Stripe amount (in cents).
     */
    private function findPlanByAmount(int $amountCents): ?Plan
    {
        // Convert cents to euros (Stripe uses cents)
        $amountEuros = $amountCents / 100;
        
        // Find plan with matching price
        return Plan::where('active', true)
            ->where('price', $amountEuros)
            ->first();
    }

    /**
     * Sync app subscription from Stripe subscription data.
     */
    private function syncAppSubscriptionFromStripe(User $user, $stripeSubscription): void
    {
        try {
            // Get the subscription item to find the price
            $subscriptionItem = $stripeSubscription->items->data[0] ?? null;
            if (!$subscriptionItem) {
                Log::warning('No subscription items found', [
                    'subscription_id' => $stripeSubscription->id,
                    'user_id' => $user->id
                ]);
                return;
            }

            // Find plan by price amount
            $priceAmount = $subscriptionItem->price->unit_amount ?? 0;
            $plan = $this->findPlanByAmount($priceAmount);

            if (!$plan) {
                Log::warning('No matching plan found for subscription', [
                    'subscription_id' => $stripeSubscription->id,
                    'price_amount' => $priceAmount,
                    'user_id' => $user->id
                ]);
                return;
            }

            // Calculate dates
            $currentPeriodStart = \Carbon\Carbon::createFromTimestamp($stripeSubscription->current_period_start);
            $currentPeriodEnd = \Carbon\Carbon::createFromTimestamp($stripeSubscription->current_period_end);

            // Map Stripe status to app status
            $appStatus = $this->mapStripeStatusToAppStatus($stripeSubscription->status);

            // Update or create app subscription
            $appSubscription = $user->subscriptions()->where('status', 'active')->first();
            
            if ($appSubscription) {
                // Update existing subscription
                $appSubscription->update([
                    'plan_id' => $plan->id,
                    'status' => $appStatus,
                    'expires_at' => $currentPeriodEnd,
                    'renews_at' => $currentPeriodEnd,
                    'canceled_at' => $stripeSubscription->status === 'canceled' ? now() : null,
                ]);
                
                Log::info('Synced existing app subscription from Stripe', [
                    'subscription_id' => $appSubscription->id,
                    'plan_id' => $plan->id,
                    'status' => $appStatus,
                    'user_id' => $user->id
                ]);
            } else {
                // Create new subscription
                $appSubscription = AppSubscription::create([
                    'user_id' => $user->id,
                    'plan_id' => $plan->id,
                    'status' => $appStatus,
                    'started_at' => $currentPeriodStart,
                    'expires_at' => $currentPeriodEnd,
                    'renews_at' => $currentPeriodEnd,
                    'canceled_at' => $stripeSubscription->status === 'canceled' ? now() : null,
                ]);
                
                Log::info('Created new app subscription from Stripe', [
                    'subscription_id' => $appSubscription->id,
                    'plan_id' => $plan->id,
                    'status' => $appStatus,
                    'user_id' => $user->id
                ]);
            }

        } catch (\Exception $e) {
            Log::error('Error syncing app subscription from Stripe', [
                'user_id' => $user->id,
                'stripe_subscription_id' => $stripeSubscription->id,
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    /**
     * Map Stripe subscription status to app subscription status.
     */
    private function mapStripeStatusToAppStatus(string $stripeStatus): string
    {
        return match($stripeStatus) {
            'active' => 'active',
            'trialing' => 'trial',
            'canceled' => 'canceled',
            'incomplete', 'incomplete_expired', 'past_due', 'unpaid' => 'expired',
            default => 'canceled'
        };
    }
}
