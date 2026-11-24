
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Datenbankverbindung testen
    if (url.pathname === "/api/health") {
      try {
        await env.DB.prepare("SELECT 1 AS ok").first();

        return Response.json({
          success: true,
          website: "Nexora Search",
          database: "connected"
        });
      } catch (error) {
        return Response.json({
          success: false,
          database: "unavailable"
        }, { status: 503 });
      }
    }

    // Website-Dateien ausliefern
    return env.ASSETS.fetch(request);
  }
};
