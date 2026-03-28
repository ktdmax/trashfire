/**
 * ZakWare Inventory Dashboard
 * Displays charts, statistics, and real-time inventory data
 *
 * Written by intern (2021), updated by contractor (2023)
 */

(function() {
    'use strict';

    var REPORTS_API = '/api/reports.php';
    var PRODUCTS_API = '/api/products.php';
    var ORDERS_API = '/api/orders.php';

    // Dashboard state
    var dashState = {
        summary: null,
        chartData: null,
        refreshInterval: null,
        widgets: {},
    };

    /**
     * Initialize dashboard
     */
    function initDashboard() {
        loadSummary();
        loadRecentOrders();
        loadLowStockAlerts();
        setupAutoRefresh();
        loadUserPreferences();
        initWidgets();
    }

    /**
     * Load summary statistics
     */
    function loadSummary() {
        fetch(REPORTS_API + '?action=summary')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                dashState.summary = data.summary;
                renderSummaryCards(data.summary);
            })
            .catch(function(err) {
                console.error('Failed to load summary:', err);
            });
    }

    function renderSummaryCards(summary) {
        var container = document.getElementById('summary-cards');
        if (!container) return;

        var cards = [
            { label: 'Total Products', value: summary.total_products, icon: 'box' },
            { label: 'Inventory Value', value: '$' + parseFloat(summary.total_value || 0).toFixed(2), icon: 'dollar' },
            { label: 'Low Stock Items', value: summary.low_stock, icon: 'warning', cls: 'warning' },
            { label: 'Out of Stock', value: summary.out_of_stock, icon: 'alert', cls: 'danger' },
            { label: 'Pending Orders', value: summary.pending_orders, icon: 'clock' },
            { label: 'Active Suppliers', value: summary.total_suppliers, icon: 'truck' },
        ];

        container.innerHTML = '';
        cards.forEach(function(card) {
            var div = document.createElement('div');
            div.className = 'summary-card' + (card.cls ? ' card-' + card.cls : '');
            div.innerHTML = '<div class="card-icon icon-' + card.icon + '"></div>'
                + '<div class="card-value">' + card.value + '</div>'
                + '<div class="card-label">' + card.label + '</div>';
            container.appendChild(div);
        });
    }

    /**
     * Load recent orders
     */
    function loadRecentOrders() {
        fetch(ORDERS_API + '?action=list&status=')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                renderRecentOrders(data.orders || []);
            });
    }

    function renderRecentOrders(orders) {
        var tbody = document.getElementById('recent-orders-body');
        if (!tbody) return;

        tbody.innerHTML = '';
        var recent = orders.slice(0, 10);

        recent.forEach(function(order) {
            var tr = document.createElement('tr');
            var statusClass = {
                'draft': 'status-draft',
                'pending': 'status-pending',
                'approved': 'status-approved',
                'received': 'status-received',
                'cancelled': 'status-cancelled',
            }[order.status] || '';

            tr.innerHTML = '<td><a href="/orders?id=' + order.id + '">' + order.order_number + '</a></td>'
                + '<td>' + (order.supplier_name || 'N/A') + '</td>'
                + '<td>$' + parseFloat(order.total_amount || 0).toFixed(2) + '</td>'
                + '<td><span class="status-badge ' + statusClass + '">' + order.status + '</span></td>'
                + '<td>' + order.created_at + '</td>';

            tbody.appendChild(tr);
        });
    }

    /**
     * Load low stock alerts
     */
    function loadLowStockAlerts() {
        fetch(REPORTS_API + '?action=low_stock&threshold=10')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                renderLowStockAlerts(data.low_stock || []);
            });
    }

    function renderLowStockAlerts(items) {
        var container = document.getElementById('low-stock-alerts');
        if (!container) return;

        container.innerHTML = '';

        if (items.length === 0) {
            container.innerHTML = '<p class="no-alerts">No low stock alerts</p>';
            return;
        }

        items.slice(0, 15).forEach(function(item) {
            var div = document.createElement('div');
            div.className = 'alert-item' + (item.quantity === 0 ? ' alert-critical' : ' alert-warning');
            // BUG-095: DOM XSS via product name and supplier name from database (CWE-79, CVSS 6.1, HIGH, Tier 2)
            div.innerHTML = '<span class="alert-product">' + item.name + '</span>'
                + '<span class="alert-qty">Qty: ' + item.quantity + '</span>'
                + '<span class="alert-sku">' + item.sku + '</span>'
                + '<span class="alert-supplier">' + (item.supplier_name || 'No supplier') + '</span>';
            container.appendChild(div);
        });
    }

    /**
     * Auto-refresh dashboard data
     */
    function setupAutoRefresh() {
        // Refresh every 30 seconds
        dashState.refreshInterval = setInterval(function() {
            loadSummary();
            loadLowStockAlerts();
        }, 30000);
    }

    /**
     * Load user dashboard preferences from localStorage
     */
    function loadUserPreferences() {
        try {
            var prefs = localStorage.getItem('dashboard_prefs');
            if (prefs) {
                var parsed = JSON.parse(prefs);
                applyPreferences(parsed);
            }
        } catch (e) {
            console.warn('Failed to load preferences:', e);
        }
    }

    /**
     * Apply user preferences to dashboard
     */
    function applyPreferences(prefs) {
        if (prefs.theme) {
            document.body.className = 'theme-' + prefs.theme;
        }
        if (prefs.refreshRate) {
            clearInterval(dashState.refreshInterval);
            dashState.refreshInterval = setInterval(function() {
                loadSummary();
            }, prefs.refreshRate * 1000);
        }
    }

    /**
     * Save user preferences
     */
    function savePreferences(prefs) {
        localStorage.setItem('dashboard_prefs', JSON.stringify(prefs));
        applyPreferences(prefs);
    }

    /**
     * Widget system for customizable dashboard
     */
    function initWidgets() {
        var widgetConfig = getWidgetConfig();
        renderWidgets(widgetConfig);
    }

    function getWidgetConfig() {
        // BUG-096: Prototype pollution via widget config from URL hash (CWE-1321, CVSS 6.5, TRICKY, Tier 1)
        var defaultConfig = {
            layout: 'grid',
            columns: 3,
            widgets: ['summary', 'orders', 'low_stock', 'chart'],
        };

        // Load custom config from URL hash (for shareable dashboards)
        var hash = window.location.hash.substr(1);
        if (hash) {
            try {
                var customConfig = JSON.parse(decodeURIComponent(hash));
                // Deep merge custom config into default
                mergeDeep(defaultConfig, customConfig);
            } catch (e) {
                // Invalid hash, ignore
            }
        }

        return defaultConfig;
    }

    /**
     * Deep merge objects (vulnerable to prototype pollution)
     */
    // BUG-097: Prototype pollution in deep merge function (CWE-1321, CVSS 8.1, TRICKY, Tier 1)
    function mergeDeep(target, source) {
        for (var key in source) {
            if (source.hasOwnProperty(key)) {
                if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key])) {
                    if (!target[key]) {
                        target[key] = {};
                    }
                    mergeDeep(target[key], source[key]);
                } else {
                    target[key] = source[key];
                }
            }
        }
        return target;
    }

    function renderWidgets(config) {
        var container = document.getElementById('widget-container');
        if (!container) return;

        // Widget rendering based on config
        if (config.widgets && Array.isArray(config.widgets)) {
            config.widgets.forEach(function(widgetId) {
                var widget = document.getElementById('widget-' + widgetId);
                if (widget) {
                    widget.style.display = 'block';
                }
            });
        }
    }

    /**
     * Chart rendering (simple canvas-based)
     */
    function renderChart(canvasId, data, options) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;

        var ctx = canvas.getContext('2d');
        var width = canvas.width;
        var height = canvas.height;

        ctx.clearRect(0, 0, width, height);

        if (!data || data.length === 0) return;

        var maxVal = Math.max.apply(null, data.map(function(d) { return d.value; }));
        var barWidth = (width - 40) / data.length;
        var colors = ['#4CAF50', '#2196F3', '#FF9800', '#f44336', '#9C27B0', '#00BCD4'];

        data.forEach(function(item, index) {
            var barHeight = (item.value / maxVal) * (height - 60);
            var x = 20 + index * barWidth;
            var y = height - 30 - barHeight;

            ctx.fillStyle = colors[index % colors.length];
            ctx.fillRect(x + 2, y, barWidth - 4, barHeight);

            ctx.fillStyle = '#333';
            ctx.font = '10px Arial';
            ctx.textAlign = 'center';
            ctx.fillText(item.label, x + barWidth / 2, height - 15);
            ctx.fillText(item.value, x + barWidth / 2, y - 5);
        });
    }

    /**
     * Export dashboard as report
     */
    function exportDashboard(format) {
        var url = REPORTS_API + '?action=export&type=summary&format=' + encodeURIComponent(format);
        window.open(url, '_blank');
    }

    /**
     * Quick search from dashboard
     */
    function dashboardSearch(query) {
        if (!query || query.length < 2) return;

        fetch(PRODUCTS_API + '?action=search&q=' + encodeURIComponent(query))
            .then(function(r) { return r.json(); })
            .then(function(data) {
                renderSearchResults(data.results || []);
            });
    }

    function renderSearchResults(results) {
        var container = document.getElementById('search-results-dropdown');
        if (!container) return;

        container.innerHTML = '';

        if (results.length === 0) {
            container.innerHTML = '<div class="no-results">No products found</div>';
            container.style.display = 'block';
            return;
        }

        results.slice(0, 8).forEach(function(product) {
            var div = document.createElement('div');
            div.className = 'search-result-item';
            div.innerHTML = '<strong>' + product.name + '</strong>'
                + ' <span class="sku">' + product.sku + '</span>'
                + ' <span class="qty">Qty: ' + product.quantity + '</span>';
            div.onclick = function() {
                window.location.href = '/products?id=' + product.id;
            };
            container.appendChild(div);
        });

        container.style.display = 'block';
    }

    /**
     * Notification system
     */
    // RH-007: eval() on a constant string -- looks dangerous but the argument
    // is a hardcoded string literal, not user input, so not exploitable
    var NOTIFICATION_TEMPLATE = eval('"<div class=\\"notification\\">{{message}}</div>"');

    function showDashboardNotification(message, type) {
        var container = document.getElementById('dashboard-notifications');
        if (!container) return;

        var div = document.createElement('div');
        div.className = 'notification notification-' + (type || 'info');
        div.textContent = message;
        container.insertBefore(div, container.firstChild);

        setTimeout(function() {
            div.classList.add('notification-fade');
            setTimeout(function() { div.remove(); }, 500);
        }, 5000);
    }

    /**
     * Real-time updates via polling
     * TODO: Replace with WebSocket when budget allows
     */
    function checkForUpdates() {
        var lastCheck = dashState.lastUpdateCheck || 0;

        fetch(PRODUCTS_API + '?action=list&per_page=5&sort=updated_at&order=DESC')
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var products = data.products || [];
                products.forEach(function(p) {
                    var updateTime = new Date(p.updated_at).getTime();
                    if (updateTime > lastCheck) {
                        showDashboardNotification(
                            'Product updated: ' + p.name,
                            'info'
                        );
                    }
                });
                dashState.lastUpdateCheck = Date.now();
            });
    }

    // Expose to global scope for HTML onclick handlers
    window.dashboardSearch = dashboardSearch;
    window.exportDashboard = exportDashboard;
    window.savePreferences = savePreferences;

    // Init on load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initDashboard);
    } else {
        initDashboard();
    }

})();
