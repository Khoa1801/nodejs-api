const express = require("express");
const router = express.Router();
const crypto = require("crypto");
const axios = require("axios");
const db = require("./index");
// const sendOrderConfirmationEmail = require("../src/component/SendMailMomo");

// Tạo thanh toán MoMo
router.post("/create_momo_payment", async (req, res) => {
  const {
    amount,
    orderInfo = "Thanh toán MoMo",
    returnUrl = "http://localhost:3000/thankyou",
    paymentCode = "",
  } = req.body;

  if (!amount || !orderInfo) {
    return res.status(400).json({ error: "Thiếu amount hoặc orderInfo" });
  }

  const partnerCode = process.env.MOMO_PARTNER_CODE || "MOMO";
  const accessKey = process.env.MOMO_ACCESS_KEY || "F8BBA842ECF85";
  const secretKey = process.env.MOMO_SECRET_KEY || "K951B6PE1waDMi640xX08PD3vg6EkVlz";

  const requestId = partnerCode + Date.now();
  const orderId = requestId;
  const ipnUrl = "http://localhost:3000/ipn_momo";
  const redirectUrl = returnUrl;
  const requestType = "payWithMethod";
  const extraData = "";
  const autoCapture = true;
  const lang = "vi";

  const rawSignature =
    `accessKey=${accessKey}` +
    `&amount=${amount}` +
    `&extraData=${extraData}` +
    `&ipnUrl=${ipnUrl}` +
    `&orderId=${orderId}` +
    `&orderInfo=${orderInfo}` +
    `&partnerCode=${partnerCode}` +
    `&redirectUrl=${redirectUrl}` +
    `&requestId=${requestId}` +
    `&requestType=${requestType}`;

  const signature = crypto.createHmac("sha256", secretKey).update(rawSignature).digest("hex");

  const requestBody = {
    partnerCode,
    partnerName: "Test Store",
    storeId: "MomoStore01",
    requestId,
    amount,
    orderId,
    orderInfo,
    redirectUrl,
    ipnUrl,
    lang,
    requestType,
    autoCapture,
    extraData,
    signature,
  };

  try {
    const momoRes = await axios.post("https://test-payment.momo.vn/v2/gateway/api/create", requestBody);
    res.json(momoRes.data);
  } catch (err) {
    console.error("❌ MoMo Payment Error:", err.response?.data || err.message);
    res.status(500).json({ error: "Không thể tạo thanh toán MoMo" });
  }
});

// Xử lý IPN từ MoMo
router.post("/ipn_momo", async (req, res) => {
  const {
    orderId,
    amount,
    resultCode,
    message,
    signature,
    extraData,
    transId,
    requestId,
    responseTime,
    orderInfo,
    payType,
    partnerCode,
    orderType,
  } = req.body;

  const secretKey = process.env.MOMO_SECRET_KEY || "K951B6PE1waDMi640xX08PD3vg6EkVlz";
  const accessKey = process.env.MOMO_ACCESS_KEY || "F8BBA842ECF85";

  const rawSignature =
    `accessKey=${accessKey}` +
    `&amount=${amount}` +
    `&extraData=${extraData}` +
    `&message=${message}` +
    `&orderId=${orderId}` +
    `&orderInfo=${orderInfo}` +
    `&orderType=${orderType}` +
    `&partnerCode=${partnerCode}` +
    `&payType=${payType}` +
    `&requestId=${requestId}` +
    `&responseTime=${responseTime}` +
    `&resultCode=${resultCode}` +
    `&transId=${transId}`;

  const expectedSignature = crypto.createHmac("sha256", secretKey).update(rawSignature).digest("hex");

  if (signature !== expectedSignature) {
    return res.status(400).json({ message: "Chữ ký không hợp lệ" });
  }

  try {
    if (Number(resultCode) === 0) {
      // Cập nhật trạng thái đơn hàng => "Đã thanh toán"
      const updateQuery = `
        UPDATE don_hang
        SET trang_thai_thanh_toan = ?, trang_thai = ?, ngay_cap_nhat = NOW()
        WHERE id_dh = ?
      `;
      db.query(updateQuery, ["Đã thanh toán", "Đang xử lý", orderId], async (err) => {
        if (err) {
          console.error("❌ Lỗi cập nhật đơn hàng:", err);
          return res.status(500).json({ message: "Cập nhật đơn hàng thất bại" });
        }

        // Gửi email xác nhận
        await sendOrderConfirmationEmail(orderId);
        return res.status(200).json({ message: "IPN thành công, đã gửi mail xác nhận." });
      });
    } else {
      // Trường hợp thanh toán thất bại
      const failQuery = `
        UPDATE don_hang
        SET trang_thai_thanh_toan = ?, ngay_cap_nhat = NOW()
        WHERE id_dh = ?
      `;
      db.query(failQuery, ["Thất bại", orderId], (err) => {
        if (err) {
          console.error("❌ Lỗi cập nhật thất bại:", err);
          return res.status(500).json({ message: "Không thể cập nhật trạng thái thất bại" });
        }

        return res.status(400).json({ message: `Thanh toán thất bại: ${message}` });
      });
    }
  } catch (err) {
    console.error("❌ Lỗi xử lý IPN:", err.message);
    return res.status(500).json({ error: "Lỗi xử lý IPN từ server" });
  }
});

module.exports = router;
