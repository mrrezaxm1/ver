

export const config = { runtime: "edge" };

// ========== تنظیمات از Environment Variables ==========
const TARGET_BASE = (process.env.TARGET_DOMAIN || "").replace(/\/$/, "");
const API_KEY = process.env.API_KEY;           // اجباری: یک کلید قوی مثل "x7k9m2p4q8r1"
const ALLOWED_PATH = process.env.ALLOWED_PATH || "/api/xhttp";  // مسیر مجاز روی سرور Xray

// ========== محدودیت‌های سخت ==========
const MAX_BODY_SIZE = 2 * 1024 * 1024;         // حداکثر ۲ مگابایت (برای جلوگیری از بارگذاری فایل)
const ALLOWED_METHODS = ["POST"];               // XHTTP فقط POST نیاز دارد
const STRIP_HEADERS = [
  "host", "connection", "keep-alive", "transfer-encoding",
  "x-vercel-*", "x-forwarded-*", "cf-*", "x-real-ip"
];

// ========== هندلر اصلی ==========
export default async function handler(req) {
  try {
    // 1. بررسی اولیه تنظیمات
    if (!TARGET_BASE || !API_KEY) {
      console.error("Missing env: TARGET_DOMAIN or API_KEY");
      return new Response("Service misconfigured", { status: 500 });
    }

    // 2. احراز هویت قوی (در هدر x-api-key)
    const clientKey = req.headers.get("x-api-key");
    if (clientKey !== API_KEY) {
      // پاسخ کوتاه بدون اطلاعات اضافی
      return new Response("Unauthorized", { status: 401 });
    }

    // 3. بررسی متد HTTP
    if (!ALLOWED_METHODS.includes(req.method)) {
      return new Response("Method not allowed", { status: 405 });
    }

    // 4. بررسی مسیر درخواست (فقط یک path خاص اجازه دارد)
    const url = new URL(req.url);
    if (url.pathname !== "/api/proxy") {
      return new Response("Not found", { status: 404 });
    }

    // 5. محدودیت حجم بدنه (برای جلوگیری از آپلود فایل)
    const contentLength = parseInt(req.headers.get("content-length") || "0");
    if (contentLength > MAX_BODY_SIZE) {
      return new Response("Payload too large", { status: 413 });
    }

    // 6. ساخت آدرس مقصد (سرور Xray شما)
    // فرض می‌کنیم TARGET_BASE مثل https://your-server.com:2096 است
    // مسیر درخواست را به همان مسیر مشخص شده هدایت می‌کنیم
    const targetUrl = `${TARGET_BASE}${ALLOWED_PATH}${url.search}`;

    // 7. فیلتر هدرها (فقط هدرهای ضروری را می‌فرستیم)
    const outHeaders = new Headers();
    const safeHeaders = ["content-type", "user-agent", "accept", "x-api-key"];
    for (const [key, value] of req.headers.entries()) {
      const lowerKey = key.toLowerCase();
      // حذف هدرهای ممنوع و هدرهای داخلی Vercel
      if (STRIP_HEADERS.some(h => lowerKey === h || (h.endsWith("*") && lowerKey.startsWith(h.slice(0, -1))))) {
        continue;
      }
      if (safeHeaders.includes(lowerKey)) {
        outHeaders.set(key, value);
      }
    }
    // به هیچ وجه هدر host اصلی را نفرست (اجازه می‌دهیم fetch خودش مقداردهی کند)
    outHeaders.delete("host");

    // 8. ارسال درخواست به سرور واقعی Xray
    const fetchOptions = {
      method: req.method,
      headers: outHeaders,
      redirect: "manual",
    };
    // فقط برای POST بدنه را اضافه کن
    if (req.method === "POST") {
      fetchOptions.body = req.body;
    }

    const response = await fetch(targetUrl, fetchOptions);

    // 9. بازگرداندن پاسخ اما با حذف هدرهای غیرضروری
    const respHeaders = new Headers();
    // فقط هدرهای امن را برگردان
    const allowedRespHeaders = ["content-type", "content-length", "date", "cache-control"];
    for (const [key, value] of response.headers.entries()) {
      if (allowedRespHeaders.includes(key.toLowerCase())) {
        respHeaders.set(key, value);
      }
    }
    // اضافه کردن هدرهای امنیتی
    respHeaders.set("x-content-type-options", "nosniff");
    respHeaders.set("cache-control", "no-store, max-age=0");

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: respHeaders,
    });

  } catch (err) {
    console.error("Proxy error:", err);
    // خطای ساده و بی‌اطلاعات
    return new Response("Bad Gateway", { status: 502 });
  }
}