/**
 * Vercel Serverless Function — API Proxy
 *
 * Forwards all /api/* requests from Vercel to the Render backend.
 * This allows the frontend (Vercel) to communicate with the backend (Render)
 * without CORS issues.
 */

const https = require("https");
const http = require("http");

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID");

  // Handle preflight
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  const API_BASE = process.env.API_BASE_URL || "https://netwatch-sih26153-api.onrender.com";

  // Build target URL
  const path = req.url || "/";
  const targetUrl = `${API_BASE}${path}`;

  try {
    const response = await fetchAPI(targetUrl, req.method, req.headers, req.body);

    // Forward response headers
    const skipHeaders = ["transfer-encoding", "content-encoding", "connection"];
    for (const [key, value] of Object.entries(response.headers)) {
      if (!skipHeaders.includes(key.toLowerCase())) {
        res.setHeader(key, value);
      }
    }

    // Add request ID header
    const requestId = req.headers["x-request-id"] || generateId();
    res.setHeader("X-Request-ID", requestId);

    return res.status(response.statusCode).send(response.body);
  } catch (error) {
    console.error(`API proxy error: ${error.message}`);
    return res.status(502).json({
      error: true,
      message: "Backend service unavailable",
      details: error.message,
    });
  }
};

/**
 * Make HTTP/HTTPS request to the backend
 */
function fetchAPI(url, method, headers, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === "https:";
    const client = isHttps ? https : http;

    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: method,
      headers: {
        "User-Agent": "Vercel-Proxy/1.0",
        ...filterHeaders(headers),
      },
    };

    const proxyReq = client.request(options, (proxyRes) => {
      let data = "";
      proxyRes.on("data", (chunk) => (data += chunk));
      proxyRes.on("end", () => {
        resolve({
          statusCode: proxyRes.statusCode,
          headers: proxyRes.headers,
          body: data,
        });
      });
    });

    proxyReq.on("error", reject);
    proxyReq.setTimeout(30000, () => {
      proxyReq.destroy();
      reject(new Error("Request timeout"));
    });

    if (body) {
      proxyReq.write(typeof body === "string" ? body : JSON.stringify(body));
    }

    proxyReq.end();
  });
}

/**
 * Filter out hop-by-hop headers
 */
function filterHeaders(headers) {
  const filtered = {};
  const skip = ["host", "connection", "transfer-encoding", "content-length"];
  for (const [key, value] of Object.entries(headers)) {
    if (!skip.includes(key.toLowerCase())) {
      filtered[key] = value;
    }
  }
  return filtered;
}

/**
 * Generate a simple request ID
 */
function generateId() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === "x" ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}
