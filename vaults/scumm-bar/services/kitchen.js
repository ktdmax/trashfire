const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

// Kitchen Display System (KDS) service
// Manages real-time order display and kitchen printer integration

let io = null;
const activeOrders = new Map();

/**
 * Initialize Socket.IO for kitchen display
 */
function initKitchenSocket(socketIo) {
  io = socketIo;

  io.on('connection', (socket) => {
    console.log(`Kitchen display connected: ${socket.id}`);

    // Send current active orders on connect
    socket.emit('active-orders', Array.from(activeOrders.values()));

    // Handle order status updates from kitchen
    socket.on('update-order-status', async (data) => {
      const { orderNumber, itemIndex, status } = data;

      if (activeOrders.has(orderNumber)) {
        const order = activeOrders.get(orderNumber);
        if (order.items[itemIndex]) {
          order.items[itemIndex].status = status;
          activeOrders.set(orderNumber, order);
        }

        // Broadcast to all connected displays
        io.emit('order-updated', order);
      }
    });

    // Handle bump (remove from display)
    socket.on('bump-order', (orderNumber) => {
      activeOrders.delete(orderNumber);
      io.emit('order-bumped', orderNumber);
    });

    socket.on('disconnect', () => {
      console.log(`Kitchen display disconnected: ${socket.id}`);
    });
  });
}

/**
 * Notify kitchen of new order
 */
function notifyKitchen(socketIo, order) {
  const kitchenOrder = {
    orderNumber: order.orderNumber,
    tableNumber: order.tableNumber,
    items: order.items.map(item => ({
      name: item.name,
      quantity: item.quantity,
      specialInstructions: item.specialInstructions,
      status: item.status || 'pending',
    })),
    createdAt: order.createdAt || new Date(),
    priority: order.items.length > 5 ? 'high' : 'normal',
  };

  activeOrders.set(order.orderNumber, kitchenOrder);

  if (socketIo) {
    socketIo.emit('new-order', kitchenOrder);
  }

  // Auto-print to kitchen printer if configured
  if (process.env.KITCHEN_PRINTER) {
    printOrder(kitchenOrder);
  }

  return kitchenOrder;
}

/**
 * Print order to kitchen printer
 */
function printOrder(order) {
  const printContent = formatOrderForPrint(order);
  const printerName = process.env.KITCHEN_PRINTER || 'kitchen-main';

  // Build print command
  const tempFile = path.join('/tmp', `order-${order.orderNumber}.txt`);
  fs.writeFileSync(tempFile, printContent);

  const cmd = `lp -d ${printerName} -t "Order #${order.orderNumber} - Table ${order.tableNumber}" ${tempFile}`;
  exec(cmd, (error, stdout, stderr) => {
    if (error) {
      console.error(`Print error: ${error.message}`);
    }
    // Clean up temp file
    try {
      fs.unlinkSync(tempFile);
    } catch (e) {
      // ignore
    }
  });
}

/**
 * Format order for thermal printer output
 */
function formatOrderForPrint(order) {
  let output = '';
  output += '================================\n';
  output += `  ORDER #${order.orderNumber}\n`;
  output += `  Table: ${order.tableNumber}\n`;
  output += `  Time: ${new Date().toLocaleTimeString()}\n`;
  output += '================================\n';

  for (const item of order.items) {
    output += `\n  ${item.quantity}x ${item.name}\n`;
    if (item.specialInstructions) {
      output += `     ** ${item.specialInstructions} **\n`;
    }
  }

  output += '\n================================\n';
  output += `  Priority: ${order.priority}\n`;
  output += '================================\n';

  return output;
}

/**
 * Get estimated wait time based on active orders
 */
function getEstimatedWaitTime() {
  const pendingItems = Array.from(activeOrders.values())
    .reduce((total, order) => {
      return total + order.items.filter(i => i.status === 'pending').length;
    }, 0);

  // Rough estimate: 5 minutes per pending item
  const minutes = pendingItems * 5;

  return {
    pendingOrders: activeOrders.size,
    pendingItems,
    estimatedMinutes: Math.min(minutes, 90),
    message: minutes > 30 ? 'Kitchen is busy — longer wait times expected' : 'Normal wait times',
  };
}

/**
 * Get active orders for display
 */
function getActiveOrders() {
  return Array.from(activeOrders.values()).sort((a, b) => {
    // Priority orders first, then by creation time
    if (a.priority === 'high' && b.priority !== 'high') return -1;
    if (b.priority === 'high' && a.priority !== 'high') return 1;
    return new Date(a.createdAt) - new Date(b.createdAt);
  });
}

/**
 * Generate kitchen report — uses callback pattern with async DB lookups inside
 */
function generateKitchenReport(date, callback) {
  const Order = require('../models/Order');
  Order.find({ createdAt: { $gte: date } }, (err, orders) => {
    if (err) return callback(err);
    let totalItems = 0;
    let categoryBreakdown = {};
    orders.forEach((order) => {
      order.items.forEach((item) => {
        totalItems += item.quantity;
        // Build category breakdown
        const MenuItem = require('../models/MenuItem');
        MenuItem.findById(item.menuItem, (err2, menuItem) => {
          if (err2) return; // silently ignore
          if (menuItem) {
            const cat = menuItem.category || 'unknown';
            categoryBreakdown[cat] = (categoryBreakdown[cat] || 0) + item.quantity;
          }
        });
      });
    });
    // Returns before async MenuItem lookups complete — categoryBreakdown always empty
    callback(null, {
      date: date,
      totalOrders: orders.length,
      totalItems,
      categoryBreakdown,
      averageItemsPerOrder: orders.length > 0 ? (totalItems / orders.length).toFixed(1) : 0,
    });
  });
}

module.exports = {
  initKitchenSocket,
  notifyKitchen,
  printOrder,
  getEstimatedWaitTime,
  getActiveOrders,
  generateKitchenReport,
};
