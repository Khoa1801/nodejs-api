const express = require("express");
const axios = require("axios");
const moment = require("moment");
const CryptoJS = require("crypto-js");
const qs = require("qs");

const paymentZaloRouter = express.Router();

const config = {
  app_id: "2554",
  key1: "sdngKKJmqEMzvh5QQcdD2A9XBSKUNaYn",
  key2: "trMrHtvjo6myautxDUiAcYsVtaeQ8nhf",
  endpoint: "https://sb-openapi.zalopay.vn/v2/create",
};

// Tạo đơn hàng ZaloPay
paymentZaloRouter.post("/create-order", async (req, res) => {
  const { amount } = req.body;

  const transID = Math.floor(Math.random() * 1000000);
  const items = [{}];

  const embed_data = {
    redirecturl: "http://localhost:3500/payment-result?paymentMethod=zalopay",
  };

  const order = {
    app_id: config.app_id,
    app_trans_id: `${moment().format("YYMMDD")}_${transID}`,
    app_user: "user123",
    app_time: Date.now(),
    item: JSON.stringify(items),
    embed_data: JSON.stringify(embed_data),
    amount: amount,
    description: `ZaloPay Order #${transID}`,
    bank_code: "",
    // ❌ KHÔNG dùng callback_url nữa để tránh lỗi IPN
  };

  const data =
    config.app_id +
    "|" +
    order.app_trans_id +
    "|" +
    order.app_user +
    "|" +
    order.amount +
    "|" +
    order.app_time +
    "|" +
    order.embed_data +
    "|" +
    order.item;

  order.mac = CryptoJS.HmacSHA256(data, config.key1).toString();

  try {
    const { data } = await axios.post(config.endpoint, null, {
      params: order,
    });
    return res.status(200).json({ data, app_trans_id: order.app_trans_id });
  } catch (error) {
    console.error("Lỗi tạo đơn hàng:", error);
    res.status(500).json({ message: "Không tạo được đơn hàng", error });
  }
});

// ✅ Kiểm tra trạng thái đơn hàng sau khi thanh toán
paymentZaloRouter.post("/check-status-order", async (req, res) => {
  const { app_trans_id } = req.body;

  const data = `${config.app_id}|${app_trans_id}|${config.key1}`;
  const mac = CryptoJS.HmacSHA256(data, config.key1).toString();

  const postData = {
    app_id: config.app_id,
    app_trans_id,
    mac,
  };

  try {
    const result = await axios.post(
      "https://sb-openapi.zalopay.vn/v2/query",
      qs.stringify(postData),
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        }
      }
    );
    res.status(200).json(result.data);
  } catch (error) {
    console.error("Lỗi kiểm tra đơn hàng:", error);
    res.status(500).json({ message: "Không kiểm tra được trạng thái đơn hàng", error });
  }
});

module.exports = paymentZaloRouter;
