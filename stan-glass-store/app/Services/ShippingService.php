<?php

namespace App\Services;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;

class ShippingService
{
    private string $apiUrl;
    private string $apiKey;

    public function __construct()
    {
        $this->apiUrl = env('SHIPPING_API_URL', 'http://shipping-api.internal:3000');
        $this->apiKey = env('SHIPPING_API_KEY', '');
    }

    /**
     * Generate a shipping label for a completed auction payment.
     */
    public function generateLabel(object $payment, string $carrier, string $service, array $extraData = []): array
    {
        $buyer = DB::table('users')->where('id', $payment->buyer_id)->first();
        $seller = DB::table('users')->where('id', $payment->seller_id)->first();

        if (!$buyer || !$seller) {
            return ['error' => 'Buyer or seller not found'];
        }

        // BUG-0108: SSRF — carrier_api_url from user input allows attacker to target internal services (CWE-918, CVSS 7.4, HIGH, Tier 2)
        $carrierApiUrl = $extraData['carrier_api_url'] ?? $this->apiUrl;

        $labelData = [
            'carrier' => $carrier,
            'service' => $service,
            'from' => [
                'name' => $seller->name,
                'address' => $seller->address,
                'city' => $seller->city,
                'state' => $seller->state,
                'zip' => $seller->zip,
                'phone' => $seller->phone,
            ],
            'to' => [
                'name' => $buyer->name,
                'address' => $buyer->address,
                'city' => $buyer->city,
                'state' => $buyer->state,
                'zip' => $buyer->zip,
                'phone' => $buyer->phone,
            ],
            'weight' => $extraData['weight'] ?? 1.0,
            'dimensions' => $extraData['dimensions'] ?? ['length' => 10, 'width' => 8, 'height' => 6],
            'value' => $payment->amount,
            'reference' => $payment->transaction_id,
        ];

        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiKey,
                'Content-Type' => 'application/json',
            ])->post("{$carrierApiUrl}/api/v1/labels", $labelData);

            if ($response->successful()) {
                $result = $response->json();

                // Store label PDF
                if (isset($result['label_pdf_url'])) {
                    // BUG-0109: Downloads and stores PDF from attacker-controllable URL without validation — could store malicious content on the server (CWE-918, CVSS 6.5, TRICKY, Tier 3)
                    $pdfContent = Http::get($result['label_pdf_url'])->body();
                    $labelPath = "labels/{$payment->transaction_id}.pdf";
                    Storage::put($labelPath, $pdfContent);
                    $result['local_path'] = $labelPath;
                }

                // Update payment with tracking info
                DB::table('payments')->where('id', $payment->id)->update([
                    'tracking_number' => $result['tracking_number'] ?? null,
                    'shipping_label_path' => $result['local_path'] ?? null,
                    'shipping_carrier' => $carrier,
                    'shipped_at' => now(),
                    'updated_at' => now(),
                ]);

                return $result;
            }

            Log::error("Shipping API error: " . $response->body());
            return ['error' => 'Failed to generate shipping label', 'details' => $response->json()];
        } catch (\Exception $e) {
            Log::error("Shipping service exception: " . $e->getMessage());
            return ['error' => 'Shipping service unavailable: ' . $e->getMessage()];
        }
    }

    /**
     * Track a shipment by tracking number.
     */
    public function track(string $trackingNumber): array
    {
        try {
            // BUG-0085: (referenced from controller) Tracking number used directly in URL path — injection if it contains path separators or query strings
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiKey,
            ])->get("{$this->apiUrl}/api/v1/tracking/{$trackingNumber}");

            if ($response->successful()) {
                return $response->json();
            }

            return [
                'tracking_number' => $trackingNumber,
                'status' => 'unknown',
                'error' => 'Unable to fetch tracking information',
            ];
        } catch (\Exception $e) {
            return [
                'tracking_number' => $trackingNumber,
                'status' => 'error',
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Calculate shipping rates.
     */
    public function calculateRates(array $fromZip, array $toZip, float $weight, array $dimensions): array
    {
        $carriers = ['usps', 'ups', 'fedex'];
        $rates = [];

        foreach ($carriers as $carrier) {
            try {
                $response = Http::withHeaders([
                    'Authorization' => 'Bearer ' . $this->apiKey,
                ])->post("{$this->apiUrl}/api/v1/rates", [
                    'carrier' => $carrier,
                    'from_zip' => $fromZip,
                    'to_zip' => $toZip,
                    'weight' => $weight,
                    'dimensions' => $dimensions,
                ]);

                if ($response->successful()) {
                    $rates[$carrier] = $response->json()['rates'] ?? [];
                }
            } catch (\Exception $e) {
                Log::warning("Rate calculation failed for {$carrier}: " . $e->getMessage());
                $rates[$carrier] = ['error' => 'Unavailable'];
            }
        }

        return $rates;
    }

    /**
     * Validate an address against the shipping API.
     */
    public function validateAddress(array $address): array
    {
        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiKey,
            ])->post("{$this->apiUrl}/api/v1/address/validate", $address);

            return $response->json();
        } catch (\Exception $e) {
            return ['valid' => false, 'error' => $e->getMessage()];
        }
    }

    /**
     * Generate a return label.
     */
    public function generateReturnLabel(object $payment): array
    {
        // Swap from/to addresses
        $buyer = DB::table('users')->where('id', $payment->buyer_id)->first();
        $seller = DB::table('users')->where('id', $payment->seller_id)->first();

        $returnData = [
            'carrier' => $payment->shipping_carrier ?? 'usps',
            'service' => 'priority',
            'from' => [
                'name' => $buyer->name,
                'address' => $buyer->address,
                'city' => $buyer->city,
                'state' => $buyer->state,
                'zip' => $buyer->zip,
            ],
            'to' => [
                'name' => $seller->name,
                'address' => $seller->address,
                'city' => $seller->city,
                'state' => $seller->state,
                'zip' => $seller->zip,
            ],
            'reference' => "RETURN-{$payment->transaction_id}",
        ];

        try {
            $response = Http::withHeaders([
                'Authorization' => 'Bearer ' . $this->apiKey,
            ])->post("{$this->apiUrl}/api/v1/labels", $returnData);

            return $response->successful() ? $response->json() : ['error' => 'Failed to generate return label'];
        } catch (\Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }
}
