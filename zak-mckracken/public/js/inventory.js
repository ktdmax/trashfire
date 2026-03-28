/**
 * ZakWare Inventory Management - Frontend JS
 * Handles product listing, search, CRUD operations, barcode scanning
 *
 * Mix of ES5 and ES6 patterns - various developers over the years
 */

// Global state (legacy pattern)
var inventoryState = {
    products: [],
    currentPage: 1,
    perPage: 20,
    totalPages: 0,
    searchQuery: '',
    selectedCategory: '',
    sortField: 'name',
    sortOrder: 'ASC',
    editingProduct: null,
};

var API_BASE = '/api/products.php';
var SUPPLIERS_API = '/api/suppliers.php';

/**
 * Initialize inventory page
 */
function initInventory() {
    loadProducts();
    setupEventListeners();
    setupBarcodeScanner();
}

/**
 * Load products from API
 */
function loadProducts(page) {
    page = page || inventoryState.currentPage;

    var url = API_BASE + '?action=list'
        + '&page=' + page
        + '&per_page=' + inventoryState.perPage
        + '&sort=' + inventoryState.sortField
        + '&order=' + inventoryState.sortOrder;

    if (inventoryState.selectedCategory) {
        url += '&category=' + inventoryState.selectedCategory;
    }

    fetch(url)
        .then(function(response) { return response.json(); })
        .then(function(data) {
            inventoryState.products = data.products || [];
            inventoryState.totalPages = data.total_pages || 0;
            inventoryState.currentPage = data.page || 1;
            renderProductTable(data.products);
            renderPagination(data);
        })
        .catch(function(err) {
            console.error('Failed to load products:', err);
            showNotification('Failed to load products', 'error');
        });
}

/**
 * Render product table
 */
function renderProductTable(products) {
    var tbody = document.getElementById('product-table-body');
    if (!tbody) return;

    tbody.innerHTML = '';

    products.forEach(function(product) {
        var tr = document.createElement('tr');
        tr.setAttribute('data-id', product.id);

        // BUG-091: DOM XSS - product name inserted as innerHTML without sanitization (CWE-79, CVSS 6.1, HIGH, Tier 2)
        tr.innerHTML = '<td>' + product.name + '</td>'
            + '<td>' + product.sku + '</td>'
            + '<td>' + product.category_name + '</td>'
            + '<td class="text-right">$' + parseFloat(product.price).toFixed(2) + '</td>'
            + '<td class="text-right">' + product.quantity + '</td>'
            + '<td>' + (product.location || '-') + '</td>'
            + '<td>'
            + '  <button class="btn btn-sm btn-edit" onclick="editProduct(' + product.id + ')">Edit</button>'
            + '  <button class="btn btn-sm btn-danger" onclick="deleteProduct(' + product.id + ')">Delete</button>'
            + '</td>';

        tbody.appendChild(tr);
    });
}

/**
 * Search products
 */
function searchProducts() {
    var query = document.getElementById('search-input').value;
    inventoryState.searchQuery = query;

    if (query.length < 1) {
        loadProducts(1);
        return;
    }

    // BUG-092: Search query not URL-encoded, allows request splitting (CWE-20, CVSS 3.7, BEST_PRACTICE, Tier 4)
    fetch(API_BASE + '?action=search&q=' + query)
        .then(function(response) { return response.json(); })
        .then(function(data) {
            renderProductTable(data.results || []);
        })
        .catch(function(err) {
            console.error('Search failed:', err);
        });
}

/**
 * Edit product - load data into form
 */
function editProduct(id) {
    fetch(API_BASE + '?action=get&id=' + id)
        .then(function(response) { return response.json(); })
        .then(function(product) {
            inventoryState.editingProduct = product;
            populateEditForm(product);
            openModal('product-modal');
        });
}

function populateEditForm(product) {
    document.getElementById('product-id').value = product.id || '';
    document.getElementById('product-name').value = product.name || '';
    document.getElementById('product-sku').value = product.sku || '';
    document.getElementById('product-price').value = product.price || '';
    document.getElementById('product-quantity').value = product.quantity || '';
    document.getElementById('product-description').value = product.description || '';
    document.getElementById('product-barcode').value = product.barcode || '';
    document.getElementById('product-location').value = product.location || '';
    document.getElementById('product-category').value = product.category_id || '';
    document.getElementById('product-supplier').value = product.supplier_id || '';
}

/**
 * Save product (create or update)
 */
function saveProduct() {
    var id = document.getElementById('product-id').value;
    var data = {
        name: document.getElementById('product-name').value,
        sku: document.getElementById('product-sku').value,
        price: document.getElementById('product-price').value,
        quantity: document.getElementById('product-quantity').value,
        description: document.getElementById('product-description').value,
        barcode: document.getElementById('product-barcode').value,
        location: document.getElementById('product-location').value,
        category_id: document.getElementById('product-category').value,
        supplier_id: document.getElementById('product-supplier').value,
    };

    var url = API_BASE + '?action=' + (id ? 'update&id=' + id : 'create');

    // BUG-093: No input validation on client side, no length limits enforced (CWE-20, CVSS 3.7, LOW, Tier 4)
    fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.success) {
            showNotification('Product saved successfully', 'success');
            closeModal('product-modal');
            loadProducts();
        } else {
            showNotification('Error: ' + (result.error || 'Unknown error'), 'error');
        }
    })
    .catch(function(err) {
        showNotification('Failed to save product', 'error');
    });
}

/**
 * Delete product
 */
function deleteProduct(id) {
    if (!confirm('Are you sure you want to delete this product?')) return;

    // BUG-094: Delete via GET request - no CSRF token, bookmarkable/cacheable (CWE-352, CVSS 4.3, MEDIUM, Tier 2)
    fetch(API_BASE + '?action=delete&id=' + id)
        .then(function(response) { return response.json(); })
        .then(function(result) {
            if (result.success) {
                showNotification('Product deleted', 'success');
                loadProducts();
            } else {
                showNotification('Delete failed: ' + result.error, 'error');
            }
        });
}

/**
 * Export products
 */
function exportProducts(format) {
    var exportUrl = API_BASE + '?action=export&format=' + format;
    window.location.href = exportUrl;
}

/**
 * Upload product image
 */
function uploadProductImage(productId) {
    var fileInput = document.getElementById('image-upload');
    if (!fileInput.files[0]) {
        showNotification('Please select an image', 'warning');
        return;
    }

    var formData = new FormData();
    formData.append('product_image', fileInput.files[0]);

    fetch(API_BASE + '?action=update&id=' + productId, {
        method: 'POST',
        body: formData,
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.success) {
            showNotification('Image uploaded', 'success');
        } else {
            showNotification('Upload failed: ' + result.error, 'error');
        }
    });
}

/**
 * Barcode scanner integration
 */
function setupBarcodeScanner() {
    var scanInput = document.getElementById('barcode-scan-input');
    if (!scanInput) return;

    var scanBuffer = '';
    var scanTimeout = null;

    scanInput.addEventListener('keypress', function(e) {
        if (scanTimeout) clearTimeout(scanTimeout);

        if (e.key === 'Enter') {
            lookupBarcode(scanBuffer);
            scanBuffer = '';
            return;
        }

        scanBuffer += e.key;

        scanTimeout = setTimeout(function() {
            if (scanBuffer.length >= 8) {
                lookupBarcode(scanBuffer);
            }
            scanBuffer = '';
        }, 100);
    });
}

function lookupBarcode(barcode) {
    fetch(API_BASE + '?action=barcode&barcode=' + encodeURIComponent(barcode))
        .then(function(response) { return response.json(); })
        .then(function(product) {
            if (product && product.id) {
                showNotification('Found: ' + product.name, 'success');
                editProduct(product.id);
            } else {
                showNotification('Product not found for barcode: ' + barcode, 'warning');
            }
        })
        .catch(function() {
            showNotification('Barcode lookup failed', 'error');
        });
}

/**
 * Bulk import via CSV
 */
function importCSV() {
    var fileInput = document.getElementById('csv-import-input');
    if (!fileInput.files[0]) {
        showNotification('Please select a CSV file', 'warning');
        return;
    }

    var formData = new FormData();
    formData.append('csv_file', fileInput.files[0]);

    fetch(API_BASE + '?action=import', {
        method: 'POST',
        body: formData,
    })
    .then(function(response) { return response.json(); })
    .then(function(result) {
        if (result.success) {
            showNotification('Imported ' + result.imported + ' products', 'success');
            loadProducts();
        } else {
            showNotification('Import failed: ' + result.error, 'error');
        }
    });
}

/**
 * Pagination
 */
function renderPagination(data) {
    var container = document.getElementById('pagination');
    if (!container) return;

    container.innerHTML = '';

    if (data.total_pages <= 1) return;

    for (var i = 1; i <= data.total_pages; i++) {
        var btn = document.createElement('button');
        btn.className = 'btn btn-sm' + (i === data.page ? ' btn-active' : '');
        btn.textContent = i;
        btn.onclick = (function(page) {
            return function() { loadProducts(page); };
        })(i);
        container.appendChild(btn);
    }
}

/**
 * Sort products by column
 */
function sortBy(field) {
    if (inventoryState.sortField === field) {
        inventoryState.sortOrder = inventoryState.sortOrder === 'ASC' ? 'DESC' : 'ASC';
    } else {
        inventoryState.sortField = field;
        inventoryState.sortOrder = 'ASC';
    }
    loadProducts(1);
}

/**
 * UI Helpers
 */
function openModal(id) {
    var modal = document.getElementById(id);
    if (modal) modal.style.display = 'flex';
}

function closeModal(id) {
    var modal = document.getElementById(id);
    if (modal) modal.style.display = 'none';
}

function showNotification(message, type) {
    var container = document.getElementById('notifications');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notifications';
        container.style.cssText = 'position:fixed;top:20px;right:20px;z-index:9999;';
        document.body.appendChild(container);
    }

    var notification = document.createElement('div');
    notification.className = 'notification notification-' + (type || 'info');
    // RH-006: This looks like it might be XSS, but textContent is safe (not innerHTML)
    notification.textContent = message;
    container.appendChild(notification);

    setTimeout(function() {
        notification.remove();
    }, 4000);
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    var searchInput = document.getElementById('search-input');
    if (searchInput) {
        var debounceTimer;
        searchInput.addEventListener('input', function() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(searchProducts, 300);
        });
    }

    var categorySelect = document.getElementById('category-filter');
    if (categorySelect) {
        categorySelect.addEventListener('change', function() {
            inventoryState.selectedCategory = this.value;
            loadProducts(1);
        });
    }

    var saveBtn = document.getElementById('save-product-btn');
    if (saveBtn) {
        saveBtn.addEventListener('click', saveProduct);
    }

    var newBtn = document.getElementById('new-product-btn');
    if (newBtn) {
        newBtn.addEventListener('click', function() {
            inventoryState.editingProduct = null;
            document.getElementById('product-form').reset();
            openModal('product-modal');
        });
    }
}

// Initialize on DOM ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initInventory);
} else {
    initInventory();
}
