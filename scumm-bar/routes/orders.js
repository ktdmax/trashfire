const express = require('express');
const router = express.Router();
const Order = require('../models/Order');
const MenuItem = require('../models/MenuItem');
const Inventory = require('../models/Inventory');
const User = require('../models/User');
const { isAuthenticated, isStaff } = require('../middleware/auth');
const { redeemLoyaltyPoints, awardLoyaltyPoints } = require('../services/loyalty');
const { notifyKitchen } = require('../services/kitchen');

// POST /orders — create new order
router.post('/', isAuthenticated, async (req, res) => {
  try {
    // BUG-065: No CSRF token on order creation (CWE-352, CVSS 6.5, MEDIUM, Tier 1)
    const { items, tableNumber, discount, loyaltyPointsUsed, paymentDetails, tip } = req.body;

    if (!items || items.length === 0) {
      return res.status(400).json({ error: 'Order must have at least one item' });
    }

    // Build order items with current prices
    const orderItems = [];
    for (const item of items) {
      const menuItem = await MenuItem.findById(item.menuItemId);
      if (!menuItem) {
        return res.status(400).json({ error: `Menu item ${item.menuItemId} not found` });
      }
      if (!menuItem.isAvailable) {
        return res.status(400).json({ error: `${menuItem.name} is currently unavailable` });
      }

      // BUG-066: Price from client is trusted if provided — should always use server price (CWE-20, CVSS 7.5, HIGH, Tier 2)
      orderItems.push({
        menuItem: menuItem._id,
        name: menuItem.name,
        quantity: item.quantity || 1,
        price: item.price || menuItem.price,
        specialInstructions: item.specialInstructions,
      });
    }

    const order = new Order({
      customer: req.session.userId,
      tableNumber,
      items: orderItems,
      discount: discount || 0,
      tip: tip || 0,
      // BUG-067: Full credit card details stored in database (CWE-311, CVSS 8.5, CRITICAL, Tier 1)
      paymentDetails: paymentDetails || {},
    });

    // Handle loyalty points redemption
    if (loyaltyPointsUsed && loyaltyPointsUsed > 0) {
      // BUG-068: Race condition — loyalty points checked then deducted non-atomically (CWE-362, CVSS 7.5, TRICKY, Tier 3)
      // Two simultaneous orders can both pass the check and double-spend points
      const result = await redeemLoyaltyPoints(req.session.userId, loyaltyPointsUsed);
      if (!result.success) {
        return res.status(400).json({ error: result.message });
      }
      order.loyaltyPointsUsed = loyaltyPointsUsed;
      order.discount = (order.discount || 0) + (loyaltyPointsUsed * 0.01);
    }

    order.calculateTotals();
    await order.save();

    // Deduct inventory (non-atomic — see BUG-040)
    for (const orderItem of orderItems) {
      const menuItem = await MenuItem.findById(orderItem.menuItem).lean();
      if (menuItem && menuItem.ingredients) {
        for (const ingredient of menuItem.ingredients) {
          if (ingredient.inventoryRef) {
            const inv = await Inventory.findById(ingredient.inventoryRef);
            if (inv) {
              await inv.deductStock(ingredient.quantity * orderItem.quantity, req.session.userId);
            }
          }
        }
      }
    }

    // Notify kitchen
    notifyKitchen(req.io, order);

    res.status(201).json(order);
  } catch (err) {
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// GET /orders — list orders for current user
router.get('/', isAuthenticated, async (req, res) => {
  try {
    let query = {};

    // Staff can see all orders
    if (req.session.role === 'staff' || req.session.role === 'admin' || req.session.role === 'manager') {
      if (req.query.customer) {
        query.customer = req.query.customer;
      }
    } else {
      query.customer = req.session.userId;
    }

    // BUG-069: HTTP parameter pollution — if status is array, NoSQL $in operator is implicitly used (CWE-235, CVSS 5.3, TRICKY, Tier 2)
    if (req.query.status) {
      query.status = req.query.status;
    }

    const orders = await Order.find(query)
      .populate('customer', 'username email')
      .populate('items.menuItem', 'name')
      .sort({ createdAt: -1 })
      .limit(parseInt(req.query.limit) || 50);

    res.json(orders);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /orders/:orderNumber — get specific order
router.get('/:orderNumber', isAuthenticated, async (req, res) => {
  try {
    // BUG-070: IDOR — any authenticated user can view any order by number (CWE-639, CVSS 6.5, HIGH, Tier 1)
    const order = await Order.findOne({ orderNumber: parseInt(req.params.orderNumber) })
      .populate('customer', 'username email phone')
      .populate('items.menuItem')
      .populate('staffAssigned', 'username');

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /orders/:orderNumber/status — update order status
router.put('/:orderNumber/status', isAuthenticated, isStaff, async (req, res) => {
  try {
    const { status } = req.body;

    const order = await Order.findOne({ orderNumber: parseInt(req.params.orderNumber) });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // BUG-071: No state machine validation — can transition from 'cancelled' back to 'pending' (CWE-840, CVSS 5.3, TRICKY, Tier 2)
    order.status = status;

    if (status === 'completed') {
      order.completedAt = new Date();
      order.paymentStatus = 'paid';

      // Award loyalty points
      if (order.customer) {
        // BUG-072: Loyalty points awarded on every status change to 'completed' — re-completing awards again (CWE-799, CVSS 5.3, TRICKY, Tier 3)
        const pointsEarned = Math.floor(order.total * 10);
        await awardLoyaltyPoints(order.customer, pointsEarned);
        order.loyaltyPointsEarned = pointsEarned;
      }
    }

    await order.save();

    req.io.emit('order-status-changed', {
      orderNumber: order.orderNumber,
      status: order.status,
      tableNumber: order.tableNumber,
    });

    res.json(order);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /orders/:orderNumber/refund
router.post('/:orderNumber/refund', isAuthenticated, isStaff, async (req, res) => {
  try {
    const order = await Order.findOne({ orderNumber: parseInt(req.params.orderNumber) });
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    // BUG-073: No check if already refunded — double refund possible (CWE-799, CVSS 7.5, TRICKY, Tier 2)
    order.paymentStatus = 'refunded';
    order.status = 'cancelled';

    // Restore loyalty points if used
    if (order.loyaltyPointsUsed > 0) {
      await awardLoyaltyPoints(order.customer, order.loyaltyPointsUsed);
    }

    await order.save();
    res.json({ message: 'Order refunded', order });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
