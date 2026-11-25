
const ITERATIONS = 100000;
const SESSION_DAYS = 7;
const COOKIE_NAME = "nexora_session";

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2",
    salt,
    iterations: ITERATIONS,
    hash: "SHA-256"
  }, key, 256);

  return `pbkdf2$${ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const [algorithm, iterationsText, saltText, hashText] = stored.split("$");
    const iterations = Number(iterationsText);

    if (algorithm !== "pbkdf2" || !Number.isInteger(iterations) ||
        iterations < 10000 || iterations > 1000000) return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt: fromBase64Url(saltText),
      iterations,
      hash: "SHA-256"
    }, key, 256);

    return await sameBytes(
      new Uint8Array(bits),
      fromBase64Url(hashText)
    );
  } catch {
    return false;
  }
}

async function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

async function sameSecret(a, b) {
  const encoder = new TextEncoder();
  const [x, y] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b))
  ]);
  return sameBytes(new Uint8Array(x), new Uint8Array(y));
}

async function hashToken(token) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  return toBase64Url(new Uint8Array(digest));
}

function randomToken() {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const item of cookies.split(";")) {
    const index = item.indexOf("=");
    if (index < 0) continue;
    if (item.slice(0, index).trim() === name) {
      return item.slice(index + 1).trim();
    }
  }
  return "";
}

function json(data, status = 200, extraHeaders = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function sessionCookie(token, maxAge = SESSION_DAYS * 86400) {
  return `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

async function getAdmin(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return null;

  const tokenHash = await hashToken(token);

  return await env.DB.prepare(`
    SELECT admins.id, admins.username, admins.role
    FROM admin_sessions
    JOIN admins ON admins.id = admin_sessions.admin_id
    WHERE admin_sessions.token_hash = ?
      AND admin_sessions.expires_at > datetime('now')
      AND admins.active = 1
  `).bind(tokenHash).first();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        await env.DB.prepare("SELECT 1 AS ok").first();
        return json({
          success: true,
          website: "Nexora Search",
          database: "connected"
        });
      } catch {
        return json({
          success: false,
          database: "unavailable"
        }, 503);
      }
    }

    // Einmalige Erstellung des Owner-Kontos
    if (url.pathname === "/api/setup-owner") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405);
      }

      try {
        const suppliedKey = request.headers.get("x-owner-setup-key") || "";
        const expectedKey = env.OWNER_SETUP_KEY;

        if (!expectedKey || !suppliedKey ||
            !await sameSecret(suppliedKey, expectedKey)) {
          return json({ error: "Unauthorized" }, 401);
        }

        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
          return json({ error: "Invalid username" }, 400);
        }

        if (password.length < 14 || password.length > 128) {
          return json({ error: "Password must contain 14 to 128 characters" }, 400);
        }

        const existing = await env.DB
          .prepare("SELECT COUNT(*) AS total FROM admins")
          .first();

        if (existing.total > 0) {
          return json({ error: "Owner setup is already closed" }, 403);
        }

        const id = crypto.randomUUID();
        const passwordHash = await hashPassword(password);

        const result = await env.DB.prepare(`
          INSERT INTO admins (id, username, password_hash, role)
          SELECT ?, ?, ?, 'owner'
          WHERE NOT EXISTS (SELECT 1 FROM admins)
        `).bind(id, username, passwordHash).run();

        if (!result.meta || result.meta.changes !== 1) {
          return json({ error: "Owner setup is already closed" }, 403);
        }

        return json({ success: true, message: "Owner account created" });
      } catch {
        return json({ error: "Setup failed" }, 400);
      }
    }

    // Admin-Login
    if (url.pathname === "/api/admin/login") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405);
      }

      try {
        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (username.length > 32 || password.length > 128) {
          return json({ error: "Invalid username or password" }, 401);
        }

        const admin = await env.DB.prepare(`
          SELECT id, username, password_hash, role
          FROM admins
          WHERE username = ? COLLATE NOCASE AND active = 1
        `).bind(username).first();

        if (!admin || !await verifyPassword(password, admin.password_hash)) {
          return json({ error: "Invalid username or password" }, 401);
        }

        const token = randomToken();
        const tokenHash = await hashToken(token);
        const sessionId = crypto.randomUUID();

        await env.DB.prepare(`
          await env.DB.prepare(`
  INSERT INTO admin_sessions
    (id, admin_id, token_hash, expires_at, ip_address)
  VALUES (?, ?, ?, ?, ?)
`).bind(
  sessionId,
  admin.id,
  tokenHash,
  expiresAt,
  request.headers.get("CF-Connecting-IP") || "Unbekannt"
).run();
          (id, admin_id, token_hash, expires_at)
          VALUES (?, ?, ?, datetime('now', '+7 days'))
        `).bind(sessionId, admin.id, tokenHash).run();

        return json({
          success: true,
          admin: {
            username: admin.username,
            role: admin.role
          }
        }, 200, {
          "Set-Cookie": sessionCookie(token)
        });
      } catch {
        return json({ error: "Login failed" }, 400);
      }
    }

    // Prüfen, ob ein Admin angemeldet ist
    if (url.pathname === "/api/admin/me") {
      if (request.method !== "GET") {
        return json({ error: "Method not allowed" }, 405);
      }

      try {
        const admin = await getAdmin(request, env);
        if (!admin) {
          return json({ authenticated: false }, 401);
        }

        return json({
          authenticated: true,
          admin
        });
      } catch {
        return json({ error: "Session check failed" }, 500);
      }
    }

    // Admin-Logout
    if (url.pathname === "/api/admin/logout") {
      if (request.method !== "POST") {
        return json({ error: "Method not allowed" }, 405);
      }

      try {
        const token = getCookie(request, COOKIE_NAME);

        if (token) {
          await env.DB.prepare(
            "DELETE FROM admin_sessions WHERE token_hash = ?"
          ).bind(await hashToken(token)).run();
        }

        return json({ success: true }, 200, {
          "Set-Cookie": sessionCookie("", 0)
        });
      } catch {
        return json({ error: "Logout failed" }, 500);
      }
    }

    // Geschützte Dashboard-Daten
    if (url.pathname === "/api/admin/dashboard") {
      if (request.method !== "GET") {
        return json({ error: "Method not allowed" }, 405);
      }

      try {
        const admin = await getAdmin(request, env);

        if (!admin) {
          return json({ error: "Nicht angemeldet" }, 401);
        }

        if (!["owner", "admin"].includes(admin.role)) {
          return json({ error: "Keine Berechtigung" }, 403);
        }

        const [adminStats, sessionStats] = await Promise.all([
          env.DB.prepare(`
            SELECT
              COUNT(*) AS total,
              SUM(CASE WHEN active = 1 THEN 1 ELSE 0 END) AS active
            FROM admins
          `).first(),

          env.DB.prepare(`
            SELECT COUNT(*) AS total
            FROM admin_sessions
            WHERE expires_at > datetime('now')
          `).first()
        ]);

        return json({
          success: true,
          admin: {
            username: admin.username,
            role: admin.role
          },
          statistics: {
            totalAdmins: adminStats.total,
            activeAdmins: adminStats.active || 0,
            activeSessions: sessionStats.total
          }
        });
      } catch {
        return json({ error: "Dashboard konnte nicht geladen werden" }, 500);
      }
    }


    return env.ASSETS.fetch(request);
  }
};
