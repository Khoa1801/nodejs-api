const express = require("express");
const crypto = require("crypto");
const qs = require("qs");
const moment = require("moment");
require("dotenv").config({ path: "../.env" });  // Chỉ định đường dẫn đến .env

const router = express.Router();

const vnp_TmnCode = "D4TQI5TL";
const vnp_HashSecret = "OOSXDHZ8PUA2YM6QGXS5L6UYYMB8EQ3M";
const vnp_Url = "https://sandbox.vnpayment.vn/paymentv2/vpcpay.html";
const vnp_ReturnUrl = `${process.env.NGROK_URL}/vnpay_return`;
const vnp_IpnUrl = `${process.env.NGROK_URL}/vnpay_ipn`;

function sortObject(obj) {
  const sorted = {};
  const keys = Object.keys(obj).sort();
  for (let key of keys) {
    sorted[key] = obj[key];
  }
  return sorted;
}

// --- 3. POST /create_payment (dành cho frontend gửi POST request)
router.post("/create_payment", (req, res) => {
  const ipAddr = req.headers["x-forwarded-for"] || req.connection.remoteAddress || req.ip;
  const amount = Math.round(Number(req.body.amount));
  const bankCode = req.body.bankCode || "NCB";
  const orderInfo = req.body.orderInfo || "Thanh toán đơn hàng";

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: "Số tiền không hợp lệ!" });
  }

  const createDate = moment().format("YYYYMMDDHHmmss");
  const orderId = Date.now().toString();

  let vnp_Params = {
    vnp_Version: "2.1.0",
    vnp_Command: "pay",
    vnp_TmnCode,
    vnp_Locale: "vn",
    vnp_CurrCode: "VND",
    vnp_TxnRef: orderId,
    vnp_OrderInfo: orderInfo,
    vnp_OrderType: "fashion",
    vnp_Amount: amount * 100,
    vnp_ReturnUrl,
    // vnp_IpnUrl,
    vnp_IpAddr: ipAddr,
    vnp_CreateDate: createDate,
    vnp_BankCode: bankCode,
  };

  vnp_Params = sortObject(vnp_Params);

  const signData = qs.stringify(vnp_Params, { encode: false });
  const secureHash = crypto
    .createHmac("sha512", vnp_HashSecret)
    .update(Buffer.from(signData, "utf-8"))
    .digest("hex");

  vnp_Params.vnp_SecureHash = secureHash;

  const paymentUrl = `${vnp_Url}?${qs.stringify(vnp_Params, { encode: true })}`;
  res.json({ paymentUrl });
});

// --- 1. GET /create_payment
router.get("/create_payment", (req, res) => {
  const ipAddr = req.headers["x-forwarded-for"] || req.connection.remoteAddress || req.ip;
  const amount = Math.round(Number(req.query.amount));
  const bankCode = req.query.bankCode || "NCB";
  const orderInfo = req.query.orderInfo || "Thanh toán đơn hàng";

  if (isNaN(amount) || amount <= 0) {
    return res.status(400).json({ error: "Số tiền không hợp lệ!" });
  }

  const createDate = moment().format("YYYYMMDDHHmmss");
  const orderId = Date.now().toString();

  let vnp_Params = {
    vnp_Version: "2.1.0",
    vnp_Command: "pay",
    vnp_TmnCode,
    vnp_Locale: "vn",
    vnp_CurrCode: "VND",
    vnp_TxnRef: orderId,
    vnp_OrderInfo: orderInfo,
    vnp_OrderType: "fashion",
    vnp_Amount: amount * 100,
    vnp_ReturnUrl,
    vnp_IpnUrl,
    vnp_IpAddr: ipAddr,
    vnp_CreateDate: createDate,
    vnp_BankCode: bankCode,
  };

  vnp_Params = sortObject(vnp_Params);

  const signData = qs.stringify(vnp_Params, { encode: false });
  const secureHash = crypto
    .createHmac("sha512", vnp_HashSecret)
    .update(Buffer.from(signData, "utf-8"))
    .digest("hex");

  vnp_Params.vnp_SecureHash = secureHash;

  const paymentUrl = `${vnp_Url}?${qs.stringify(vnp_Params, { encode: true })}`;
  res.json({ paymentUrl });
});

// --- 2. GET /vnpay_return (user redirect)
router.get("/vnpay_return", (req, res) => {
  const vnp_Params = { ...req.query };
  const secureHash = vnp_Params.vnp_SecureHash;
  delete vnp_Params.vnp_SecureHash;

  const signData = qs.stringify(sortObject(vnp_Params), { encode: false });
  const checkSum = crypto
    .createHmac("sha512", vnp_HashSecret)
    .update(Buffer.from(signData, "utf-8"))
    .digest("hex");

  const status =
    secureHash === checkSum
      ? vnp_Params.vnp_ResponseCode === "00"
        ? "success"
        : "fail"
      : "invalid";

  return res.redirect(`http://localhost:5173/payment-result?status=${status}`);
});

router.get("/vnpay_ipn", (req, res) => {
  var vnp_Params = req.query;

  var secureHash = vnp_Params.vnp_SecureHash;

  delete vnp_Params.vnp_SecureHash;
  delete vnp_Params.vnp_SecureHashType;

  vnp_Params = sortObject(vnp_Params);

  var signData = qs.stringify(vnp_Params, { encode: false });
  const hmac = crypto.createHmac("sha512", vnp_HashSecret);
  var signed = hmac.update(Buffer.from(signData, 'utf-8')).digest("hex");

  if (secureHash === signed) {
    // Đúng chữ ký, xử lý đơn hàng
    console.log("✅ IPN xác minh hợp lệ");
    res.status(200).json({ RspCode: "00", Message: "OK" });
  } else {
    console.log("❌ IPN sai chữ ký");
    res.status(200).json({ RspCode: "97", Message: "Sai chữ ký" });
  }
  console.log("✅ IPN URL: ", vnp_IpnUrl);

});


module.exports = router;
