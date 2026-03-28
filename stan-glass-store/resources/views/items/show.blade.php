{{-- Stan's Glass Store - Item Detail View --}}
@extends('layouts.app')

@section('title', $item->title ?? 'Item Details')

{{-- BUG-0115: Meta tags use unescaped item data — XSS via Open Graph / meta injection (CWE-79, CVSS 4.3, LOW, Tier 3) --}}
@section('meta')
<meta property="og:title" content="{!! $item->title !!}">
<meta property="og:description" content="{!! $item->description !!}">
<meta property="og:image" content="{{ asset('storage/' . $item->photo_path) }}">
<meta name="description" content="{!! strip_tags($item->description) !!}">
@endsection

@section('content')
<div class="container mx-auto px-4 py-8">
    {{-- Breadcrumbs --}}
    <nav class="text-sm mb-6">
        <a href="{{ route('items.index') }}" class="text-blue-600 hover:underline">Items</a>
        <span class="mx-2">/</span>
        {{-- BUG-0116: Category name rendered unescaped — stored XSS if category contains malicious HTML/JS (CWE-79, CVSS 6.1, MEDIUM, Tier 2) --}}
        <span>{!! $item->category !!}</span>
        <span class="mx-2">/</span>
        <span class="text-gray-600">{{ $item->title }}</span>
    </nav>

    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {{-- Item Image --}}
        <div class="space-y-4">
            @if($item->photo_path)
                <div class="aspect-square bg-gray-100 rounded-lg overflow-hidden">
                    <img src="{{ asset('storage/' . $item->photo_path) }}"
                         alt="{{ $item->title }}"
                         class="w-full h-full object-cover">
                </div>
            @else
                <div class="aspect-square bg-gray-200 rounded-lg flex items-center justify-center">
                    <span class="text-gray-500 text-lg">No Image Available</span>
                </div>
            @endif

            {{-- Thumbnail Gallery --}}
            @if(isset($item->gallery) && is_array($item->gallery))
                <div class="grid grid-cols-4 gap-2">
                    @foreach($item->gallery as $thumb)
                        <img src="{{ asset('storage/' . $thumb) }}"
                             class="aspect-square object-cover rounded cursor-pointer hover:opacity-75"
                             onclick="document.querySelector('.main-image').src = this.src">
                    @endforeach
                </div>
            @endif
        </div>

        {{-- Item Details --}}
        <div class="space-y-6">
            <div>
                {{-- BUG-0117: Item title rendered with {!! !!} — stored XSS via item title (CWE-79, CVSS 6.1, HIGH, Tier 2) --}}
                <h1 class="text-3xl font-bold text-gray-900">{!! $item->title !!}</h1>
                <p class="text-sm text-gray-500 mt-1">Listed {{ \Carbon\Carbon::parse($item->created_at ?? now())->diffForHumans() }}</p>
            </div>

            {{-- Price / Auction Status --}}
            @if(isset($item->auction_status) && $item->auction_status === 'active')
                <div class="bg-amber-50 border border-amber-200 rounded-lg p-4">
                    <div class="flex justify-between items-center">
                        <div>
                            <span class="text-sm text-amber-800 font-medium">Current Bid</span>
                            <p class="text-2xl font-bold text-amber-900">${{ number_format($item->current_price ?? 0, 2) }}</p>
                        </div>
                        <div class="text-right">
                            <span class="text-sm text-amber-800 font-medium">Ends</span>
                            <p class="text-lg font-semibold text-amber-900" id="countdown">
                                {{ \Carbon\Carbon::parse($item->end_time)->diffForHumans() }}
                            </p>
                        </div>
                    </div>
                    <p class="text-sm text-amber-700 mt-2">{{ $item->bid_count ?? 0 }} bids &middot; Starting price: ${{ number_format($item->starting_price ?? 0, 2) }}</p>

                    {{-- Bid Form --}}
                    @auth
                        <form action="{{ route('auctions.bid', $item->auction_id) }}" method="POST" class="mt-4">
                            @csrf
                            <div class="flex gap-2">
                                <div class="flex-1">
                                    <input type="number"
                                           name="amount"
                                           step="0.01"
                                           min="{{ ($item->current_price ?? 0) + 1 }}"
                                           placeholder="Enter bid amount"
                                           class="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-amber-500"
                                           required>
                                </div>
                                <button type="submit"
                                        class="px-6 py-2 bg-amber-600 text-white font-semibold rounded-lg hover:bg-amber-700 transition">
                                    Place Bid
                                </button>
                            </div>
                        </form>
                    @else
                        <p class="mt-4 text-sm text-amber-800">
                            <a href="{{ route('login') }}" class="underline font-medium">Log in</a> to place a bid.
                        </p>
                    @endauth
                </div>
            @else
                <div class="flex items-baseline gap-2">
                    <span class="text-3xl font-bold text-green-700">${{ number_format($item->price ?? 0, 2) }}</span>
                    @if(isset($item->original_price) && $item->original_price > $item->price)
                        <span class="text-lg text-gray-400 line-through">${{ number_format($item->original_price, 2) }}</span>
                    @endif
                </div>
            @endif

            {{-- Condition Badge --}}
            <div class="flex items-center gap-3">
                <span class="px-3 py-1 text-sm font-medium rounded-full
                    @switch($item->condition ?? 'good')
                        @case('mint') bg-emerald-100 text-emerald-800 @break
                        @case('excellent') bg-blue-100 text-blue-800 @break
                        @case('good') bg-yellow-100 text-yellow-800 @break
                        @case('fair') bg-orange-100 text-orange-800 @break
                        @case('poor') bg-red-100 text-red-800 @break
                    @endswitch
                ">
                    {{ ucfirst($item->condition ?? 'Unknown') }} Condition
                </span>
                <span class="text-sm text-gray-500">{{ $item->view_count ?? 0 }} views</span>
            </div>

            {{-- Description --}}
            <div class="prose max-w-none">
                <h3 class="text-lg font-semibold text-gray-900">Description</h3>
                {{-- BUG-0118: Full description rendered unescaped — stored XSS via item description with full HTML/JS injection (CWE-79, CVSS 7.1, HIGH, Tier 1) --}}
                <div class="text-gray-700 mt-2">{!! $item->description !!}</div>
            </div>

            {{-- Item Metadata --}}
            @if(isset($item->metadata) && is_array(json_decode($item->metadata ?? '{}', true)))
                <div class="border-t pt-4">
                    <h3 class="text-lg font-semibold text-gray-900 mb-2">Details</h3>
                    <dl class="grid grid-cols-2 gap-2 text-sm">
                        @foreach(json_decode($item->metadata, true) as $key => $value)
                            <dt class="text-gray-500">{{ ucfirst($key) }}</dt>
                            {{-- BUG-0119: Metadata values rendered unescaped — XSS via item metadata fields (CWE-79, CVSS 5.4, MEDIUM, Tier 2) --}}
                            <dd class="text-gray-900">{!! $value !!}</dd>
                        @endforeach
                    </dl>
                </div>
            @endif

            {{-- Seller Info --}}
            <div class="border-t pt-4">
                <h3 class="text-lg font-semibold text-gray-900 mb-3">Seller</h3>
                <div class="flex items-center gap-4">
                    <div class="w-12 h-12 bg-gray-300 rounded-full flex items-center justify-center">
                        <span class="text-lg font-bold text-gray-600">
                            {{ strtoupper(substr($item->seller_name ?? 'U', 0, 1)) }}
                        </span>
                    </div>
                    <div>
                        <p class="font-medium text-gray-900">{{ $item->seller_name ?? 'Unknown Seller' }}</p>
                        {{-- BUG-0120: Seller email displayed to all viewers — PII disclosure, enables phishing/spam (CWE-200, CVSS 3.7, BEST_PRACTICE, Tier 4) --}}
                        <p class="text-sm text-gray-500">{{ $item->seller_email ?? '' }}</p>
                        @if(isset($item->reputation_score))
                            <div class="flex items-center mt-1">
                                @for($i = 1; $i <= 5; $i++)
                                    <svg class="w-4 h-4 {{ $i <= round($item->reputation_score) ? 'text-yellow-400' : 'text-gray-300' }}"
                                         fill="currentColor" viewBox="0 0 20 20">
                                        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
                                    </svg>
                                @endfor
                                <span class="ml-1 text-sm text-gray-600">({{ number_format($item->reputation_score, 1) }})</span>
                            </div>
                        @endif
                        {{-- BUG-0121: Seller phone number displayed publicly (CWE-200, CVSS 3.1, BEST_PRACTICE, Tier 4) --}}
                        @if(isset($item->seller_phone))
                            <p class="text-sm text-gray-500 mt-1">Phone: {{ $item->seller_phone }}</p>
                        @endif
                    </div>
                </div>
            </div>
        </div>
    </div>

    {{-- Auction Bid History --}}
    @if(isset($item->auction_id))
        <div class="mt-12">
            <h2 class="text-2xl font-bold text-gray-900 mb-4">Bid History</h2>
            <div id="bid-history" class="bg-white rounded-lg shadow overflow-hidden">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Bidder</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Amount</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-200" id="bid-rows">
                        {{-- Populated via Livewire or AJAX --}}
                    </tbody>
                </table>
            </div>
        </div>
    @endif

    {{-- Report / Share Section --}}
    <div class="mt-8 flex items-center gap-4">
        <button onclick="navigator.share({title: '{{ $item->title }}', url: window.location.href})"
                class="text-sm text-gray-600 hover:text-gray-900 flex items-center gap-1">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/>
            </svg>
            Share
        </button>

        <a href="/report?item_id={{ $item->id }}" class="text-sm text-red-600 hover:text-red-800 flex items-center gap-1">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4.5c-.77-.833-2.694-.833-3.464 0L3.34 16.5c-.77.833.192 2.5 1.732 2.5z"/>
            </svg>
            Report Listing
        </a>
    </div>
</div>

{{-- Countdown Timer Script --}}
@if(isset($item->end_time))
<script>
    // BUG-0122: Item ID directly interpolated into JavaScript — DOM XSS if ID is controllable or reflected from URL (CWE-79, CVSS 4.3, LOW, Tier 3)
    const itemId = {!! json_encode($item->id) !!};
    const endTime = new Date("{!! $item->end_time !!}").getTime();

    function updateCountdown() {
        const now = new Date().getTime();
        const distance = endTime - now;

        if (distance < 0) {
            document.getElementById('countdown').innerHTML = 'Auction Ended';
            return;
        }

        const hours = Math.floor(distance / (1000 * 60 * 60));
        const minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((distance % (1000 * 60)) / 1000);

        document.getElementById('countdown').innerHTML =
            `${hours}h ${minutes}m ${seconds}s remaining`;
    }

    setInterval(updateCountdown, 1000);
    updateCountdown();

    // Live bid updates via polling
    function fetchBids() {
        fetch(`/api/v1/auctions/${itemId}/bids`)
            .then(r => r.json())
            .then(data => {
                const rows = document.getElementById('bid-rows');
                if (!rows || !data.bids) return;

                rows.innerHTML = data.bids.map(bid => `
                    <tr>
                        <td class="px-6 py-4 text-sm text-gray-900">${bid.bidder_name}</td>
                        <td class="px-6 py-4 text-sm font-medium text-gray-900">$${parseFloat(bid.amount).toFixed(2)}</td>
                        <td class="px-6 py-4 text-sm text-gray-500">${new Date(bid.created_at).toLocaleString()}</td>
                    </tr>
                `).join('');
            })
            .catch(err => console.warn('Failed to fetch bids:', err));
    }

    // BUG-0123: Bid data inserted via innerHTML without sanitization — DOM XSS if bidder_name contains HTML/JS (CWE-79, CVSS 6.1, TRICKY, Tier 3)
    setInterval(fetchBids, 5000);
    fetchBids();
</script>
@endif

{{-- Inline Sharing Widget --}}
<script>
    // BUG-0124: URL parameter read directly and injected into DOM — reflected DOM XSS via URL hash/params (CWE-79, CVSS 6.1, TRICKY, Tier 3)
    const urlParams = new URLSearchParams(window.location.search);
    const refMessage = urlParams.get('ref_msg');
    if (refMessage) {
        const banner = document.createElement('div');
        banner.className = 'bg-blue-100 text-blue-800 p-3 text-center text-sm rounded mb-4';
        banner.innerHTML = refMessage;
        document.querySelector('.container')?.prepend(banner);
    }
</script>
@endsection
