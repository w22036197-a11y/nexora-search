
const ITERATIONS = 100000;

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hashPassword(password) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$${ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}

async function sameSecret(a, b) {
  const encoder = new TextEncoder();
  const [hashA, hashB] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(a)),
    crypto.subtle.digest("SHA-256", encoder.encode(b))
  ]);

  const x = new Uint8Array(hashA);
  const y = new Uint8Array(hashB);
  let difference = 0;

  for (let i = 0; i < x.length; i++) {
    difference |= x[i] ^ y[i];
  }

  return difference === 0;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        await env.DB.prepare("SELECT 1 AS ok").first();
        return Response.json({
          success: true,
          website: "Nexora Search",
          database: "connected"
        });
      } catch {
        return Response.json({
          success: false,
          database: "unavailable"
        }, { status: 503 });
      }
    }

    if (url.pathname === "/api/setup-owner") {
      if (request.method !== "POST") {
        return Response.json({ error: "Method not allowed" }, { status: 405 });
      }

      try {
        const suppliedKey = request.headers.get("x-owner-setup-key") || "";

        if (!await sameSecret(suppliedKey, env.OWNER_SETUP_KEY || "")) {
          return Response.json({ error: "Unauthorized" }, { status: 401 });
        }

        const body = await request.json();
        const username = String(body.username || "").trim();
        const password = String(body.password || "");

        if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username)) {
          return Response.json({ error: "Invalid username" }, { status: 400 });
        }

        if (password.length < 14 || password.length > 128) {
          return Response.json({
            error: "Password must contain 14 to 128 characters"
          }, { status: 400 });
        }

        const existing = await env.DB
          .prepare("SELECT COUNT(*) AS total FROM admins")
          .first();

        if (existing.total > 0) {
          return Response.json({
            error: "Owner setup is already closed"
          }, { status: 403 });
        }

        const id = crypto.randomUUID();
        const passwordHash = await hashPassword(password);

        const result = await env.DB.prepare(`
          INSERT INTO admins (id, username, password_hash, role)
          SELECT ?, ?, ?, 'owner'
          WHERE NOT EXISTS (SELECT 1 FROM admins)
        `).bind(id, username, passwordHash).run();

        if (!result.meta || result.meta.changes !== 1) {
          return Response.json({
            error: "Owner setup is already closed"
          }, { status: 403 });
        }

        return Response.json({
          success: true,
          message: "Owner account created"
        });
      } catch {
        return Response.json({
          error: "Setup failed"
        }, { status: 400 });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
