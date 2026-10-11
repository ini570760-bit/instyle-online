export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // API — ESTADO DEL SITIO
    // =========================

    if (url.pathname === "/api/state") {
      // Leer estado público
      if (request.method === "GET") {
        try {
          const rows = await env.DB
            .prepare("SELECT state_key, state_value FROM site_state")
            .all();

          const state = {};

          for (const row of rows.results || []) {
            state[row.state_key] = row.state_value;
          }

          return json({ state });
        } catch (error) {
          return json(
            { message: "No se pudo leer el estado del sitio." },
            500
          );
        }
      }

      // Guardar estado — solo administración
      if (request.method === "POST") {
        if (!isAdmin(request)) {
          return json({ message: "No autorizado." }, 401);
        }

        try {
          const body = await request.json();

          // Guardado de una sola clave
          if (body.key) {
            await saveStateKey(env.DB, body.key, body.value);
            return json({ ok: true });
          }

          // Guardado completo
          if (body.state && typeof body.state === "object") {
            for (const [key, value] of Object.entries(body.state)) {
              await saveStateKey(env.DB, key, value);
            }

            return json({ ok: true });
          }

          return json({ message: "Estado inválido." }, 400);
        } catch (error) {
          return json(
            { message: "No se pudo guardar el estado." },
            500
          );
        }
      }

      return json({ message: "Método no permitido." }, 405);
    }

    // =========================
    // API — MENSAJES
    // =========================

    if (url.pathname === "/api/messages") {

      // Limpiar mensajes con más de 3 días
      await cleanupMessages(env.DB);

      // Enviar mensaje desde el formulario
      if (request.method === "POST") {
        try {
          const form = await request.formData();

          const category = clean(form.get("category"));
          const name = clean(form.get("name"));
          const email = clean(form.get("email"));
          const description = clean(form.get("description"));

          // Campo trampa anti-bot
          const honeypot = clean(form.get("website"));

          if (honeypot) {
            return json({ ok: true });
          }

          if (!category || !email || !description) {
            return json(
              {
                message:
                  "Completá el motivo, tu correo y la descripción."
              },
              400
            );
          }

          if (!isValidEmail(email)) {
            return json(
              { message: "Ingresá un correo válido." },
              400
            );
          }

          // Límite de seguridad para texto
          if (
            category.length > 200 ||
            name.length > 200 ||
            email.length > 320 ||
            description.length > 10000
          ) {
            return json(
              { message: "El mensaje supera el límite permitido." },
              400
            );
          }

          // Adjuntos
          const attachment = form.get("attachment");

          let attachmentName = "";
          let attachmentType = "";
          let attachmentSize = 0;

          if (
            attachment &&
            typeof attachment === "object" &&
            "name" in attachment
          ) {
            attachmentName = String(attachment.name || "");
            attachmentType = String(attachment.type || "");
            attachmentSize = Number(attachment.size || 0);

            // 8 MB máximo
            if (attachmentSize > 8 * 1024 * 1024) {
              return json(
                {
                  message:
                    "El archivo adjunto no puede superar los 8 MB."
                },
                400
              );
            }
          }

          await env.DB
            .prepare(`
              INSERT INTO messages
              (
                category,
                name,
                email,
                description,
                attachment_name,
                attachment_type,
                attachment_size,
                created_at
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `)
            .bind(
              category,
              name,
              email,
              description,
              attachmentName,
              attachmentType,
              attachmentSize,
              new Date().toISOString()
            )
            .run();

          /*
           * El envío real de correo todavía no está conectado.
           * Más adelante agregaremos el proveedor de email.
           */

          return json({
            ok: true,
            emailSent: false,
            message:
              "Mensaje recibido. El equipo de I.N STYLE lo verá pronto."
          });
        } catch (error) {
          return json(
            {
              message:
                "No pudimos recibir el mensaje. Probá nuevamente."
            },
            500
          );
        }
      }

      // Ver mensajes desde administración
      if (request.method === "GET") {
        if (!isAdmin(request)) {
          return json({ message: "No autorizado." }, 401);
        }

        try {
          const rows = await env.DB
            .prepare(`
              SELECT
                id,
                category,
                name,
                email,
                description,
                attachment_name,
                attachment_type,
                attachment_size,
                created_at
              FROM messages
              ORDER BY created_at DESC
            `)
            .all();

          return json({
            messages: rows.results || []
          });
        } catch (error) {
          return json(
            { message: "No se pudieron cargar los mensajes." },
            500
          );
        }
      }

      // Eliminar mensaje manualmente
      if (request.method === "DELETE") {
        if (!isAdmin(request)) {
          return json({ message: "No autorizado." }, 401);
        }

        try {
          const body = await request.json();
          const id = Number(body.id);

          if (!Number.isInteger(id) || id <= 0) {
            return json(
              { message: "ID de mensaje inválido." },
              400
            );
          }

          await env.DB
            .prepare("DELETE FROM messages WHERE id = ?")
            .bind(id)
            .run();

          return json({ ok: true });
        } catch (error) {
          return json(
            { message: "No se pudo eliminar el mensaje." },
            500
          );
        }
      }

      return json({ message: "Método no permitido." }, 405);
    }

    // =========================
    // ARCHIVOS DEL SITIO
    // =========================

    // Todo lo que no sea /api/* se sirve desde public/
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("I.N STYLE", {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=UTF-8"
      }
    });
  }
};


// ========================================
// FUNCIONES AUXILIARES
// ========================================

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=UTF-8",
      "cache-control": "no-store"
    }
  });
}


function isAdmin(request) {
  return (
    request.headers.get("X-INSTYLE-ADMIN") ===
    "INSTYLE2026"
  );
}


function clean(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value).trim();
}


function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


async function saveStateKey(db, key, value) {
  const stateValue =
    value === null || value === undefined
      ? null
      : String(value);

  if (stateValue === null) {
    await db
      .prepare("DELETE FROM site_state WHERE state_key = ?")
      .bind(key)
      .run();

    return;
  }

  await db
    .prepare(`
      INSERT INTO site_state
      (
        state_key,
        state_value,
        updated_at
      )
      VALUES (?, ?, ?)
      ON CONFLICT(state_key)
      DO UPDATE SET
        state_value = excluded.state_value,
        updated_at = excluded.updated_at
    `)
    .bind(
      key,
      stateValue,
      new Date().toISOString()
    )
    .run();
}


async function cleanupMessages(db) {
  const cutoff = new Date(
    Date.now() - 3 * 24 * 60 * 60 * 1000
  ).toISOString();

  await db
    .prepare(
      "DELETE FROM messages WHERE created_at < ?"
    )
    .bind(cutoff)
    .run();
}
