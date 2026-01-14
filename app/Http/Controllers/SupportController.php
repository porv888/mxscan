<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Auth;

class SupportController extends Controller
{
    public function send(Request $request)
    {
        $request->validate([
            'message' => 'required|string|min:10|max:2000',
        ]);

        $user = Auth::user();
        
        $subject = "Support Request from {$user->name} (ID: {$user->id})";
        $body = "Support request from MXScan user:\n\n";
        $body .= "User ID: {$user->id}\n";
        $body .= "Name: {$user->name}\n";
        $body .= "Email: {$user->email}\n";
        $body .= "Plan: " . ($user->currentPlan()->name ?? 'Free') . "\n";
        $body .= "---\n\n";
        $body .= "Message:\n{$request->message}";

        Mail::raw($body, function ($mail) use ($subject, $user) {
            $mail->to('hello@mxscan.me')
                 ->replyTo($user->email, $user->name)
                 ->subject($subject);
        });

        return response()->json([
            'success' => true,
            'message' => 'Your message has been sent. We\'ll get back to you soon!'
        ]);
    }
}
