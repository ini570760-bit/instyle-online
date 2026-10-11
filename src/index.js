export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // API — INICIAR SESIÓN ADMIN
    // =========================

    if (url.pathname === "/api/admin-login") {
      if (request.method !== "POST") {
        return json(
          { message: "Método no permitido." },
          405
        );
      }

      if (!env.INSTYLE_ADMIN_SECRET) {
        return json(
          { message: "La clave privada no está configurada en Cloudflare." },
          500
        );
      }

      try {
        const body = await request.json();
        const secret = String(body.secret || "");

        if (secret !== env.INSTYLE_ADMIN_SECRET) {
          return json(
            { message: "Clave incorrecta." },
            401
          );
        }

        const cookieValue = encodeURIComponent(secret);

        return new Response(
          JSON.stringify({
            ok: true,
            message: "Sesión iniciada correctamente."
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json; charset=UTF-8",
              "cache-control": "no-store",
              "set-cookie":
                `instyle_admin_session=${cookieValue}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=28800`
            }
          }
        );

      } catch (error) {
        return json(
          { message: "No se pudo iniciar la sesión." },
          400
        );
      }
    }

    // =========================
    // API — CERRAR SESIÓN ADMIN
    // =========================

    if (url.pathname === "/api/admin-logout") {
      return new Response(
        JSON.stringify({ ok: true }),
        {
          status: 200,
          headers: {
            "content-type": "application/json; charset=UTF-8",
            "cache-control": "no-store",
            "set-cookie":
              "instyle_admin_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0"
          }
        }
      );
    }

    // =========================
    // API — ESTADO DEL SITIO
    // =========================

    if (url.pathname === "/api/state") {
      if (request.method === "GET") {
        try {
          const rows = await env.DB
            .prepare(
              "SELECT state_key, state_value FROM site_state"
            )
            .all();

          const state = {};

          for (const row of rows.results || []) {
            state[row.state_key] = row.state_value;
          }

          return json({ state });

        } catch (error) {
          return json(
            {
              message: "No se pudo leer el estado del sitio."
            },
            500
          );
        }
      }

      if (request.method === "POST") {
        if (!isAdmin(request, env)) {
          return json(
            { message: "No autorizado." },
            401
          );
        }

        try {
          const body = await request.json();

          if (body.key) {
            await saveStateKey(
              env.DB,
              body.key,
              body.value
            );

            return json({ ok: true });
          }

          if (
            body.state &&
            typeof body.state === "object" &&
            !Array.isArray(body.state)
          ) {
            for (const [key, value] of Object.entries(body.state)) {
              await saveStateKey(
                env.DB,
                key,
                value
              );
            }

            return json({ ok: true });
          }

          return json(
            { message: "Estado inválido." },
            400
          );

        } catch (error) {
          return json(
            {
              message: "No se pudo guardar el estado."
            },
            500
          );
        }
      }

      return json(
        { message: "Método no permitido." },
        405
      );
    }

    // =========================
    // API — MENSAJES
    // =========================

    if (url.pathname === "/api/messages") {

      // Limpiar mensajes con más de 3 días.
      // Si falla la limpieza, continuar.
      try {
        await cleanupMessages(env.DB);
      } catch (error) {
        // No interrumpir la solicitud.
      }

      // =========================
      // RECIBIR MENSAJES
      // Formulario público
      // =========================

      if (request.method === "POST") {
        try {
          const form = await request.formData();

          const category = clean(
            form.get("category") ||
            form.get("motivo") ||
            form.get("categoria") ||
            form.get("reason")
          );

          const name = clean(
            form.get("name") ||
            form.get("nombre")
          );

          const email = clean(
            form.get("email") ||
            form.get("correo")
          );

          const description = clean(
            form.get("description") ||
            form.get("descripcion") ||
            form.get("mensaje")
          );

          // Campo trampa anti-bot
          const honeypot = clean(
            form.get("website")
          );

          if (honeypot) {
            return json({ ok: true });
          }

          // Validar campos obligatorios
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
              {
                message: "Ingresá un correo válido."
              },
              400
            );
          }

          // Límites de seguridad
          if (
            category.length > 200 ||
            name.length > 200 ||
            email.length > 320 ||
            description.length > 10000
          ) {
            return json(
              {
                message:
                  "El mensaje supera el límite permitido."
              },
              400
            );
          }

          // Datos del archivo adjunto
          const attachment = form.get("attachment");

          let attachmentName = "";
          let attachmentType = "";
          let attachmentSize = 0;

          if (
            attachment &&
            typeof attachment === "object" &&
            "name" in attachment &&
            attachment.name
          ) {
            attachmentName = String(
              attachment.name || ""
            );

            attachmentType = String(
              attachment.type || ""
            );

            attachmentSize = Number(
              attachment.size || 0
            );

            // Máximo: 8 MB
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

          // Guardar el mensaje en D1
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

      // =========================
      // CONSULTAR MENSAJES
      // Solo administración
      // =========================

      if (request.method === "GET") {
        if (!isAdmin(request, env)) {
          return json(
            { message: "No autorizado." },
            401
          );
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
            {
              message:
                "No se pudieron cargar los mensajes."
            },
            500
          );
        }
      }

      // =========================
      // ELIMINAR MENSAJES
      // Solo administración
      // =========================

      if (request.method === "DELETE") {
        if (!isAdmin(request, env)) {
          return json(
            { message: "No autorizado." },
            401
          );
        }

        try {
          const body = await request.json();
          const id = Number(body.id);

          if (!Number.isInteger(id) || id <= 0) {
            return json(
              {
                message: "ID de mensaje inválido."
              },
              400
            );
          }

          await env.DB
            .prepare(
              "DELETE FROM messages WHERE id = ?"
            )
            .bind(id)
            .run();

          return json({ ok: true });

        } catch (error) {
          return json(
            {
              message:
                "No se pudo eliminar el mensaje."
            },
            500
          );
        }
      }

      return json(
        { message: "Método no permitido." },
        405
      );
    }

    // =========================
    // ARCHIVOS DEL SITIO
    // =========================

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
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=UTF-8",
        "cache-control": "no-store"
      }
    }
  );
}


// ========================================
// VERIFICAR SESIÓN DE ADMINISTRACIÓN
// ========================================

function isAdmin(request, env) {
  const cookieHeader =
    request.headers.get("Cookie") || "";

  const sessionCookie = cookieHeader
    .split(";")
    .map(item => item.trim())
    .find(item =>
      item.startsWith("instyle_admin_session=")
    );

  if (!env.INSTYLE_ADMIN_SECRET || !sessionCookie) {
    return false;
  }

  try {
    const sessionValue = decodeURIComponent(
      sessionCookie.slice(
        "instyle_admin_session=".length
      )
    );

    return sessionValue === env.INSTYLE_ADMIN_SECRET;

  } catch (error) {
    return false;
  }
}


// ========================================
// LIMPIAR TEXTO
// ========================================

function clean(value) {
  if (value === null || value === undefined) {
    return "";
  }

  return String(value).trim();
}


// ========================================
// VALIDAR CORREO
// ========================================

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}


// ========================================
// GUARDAR ESTADO DEL SITIO
// ========================================

async function saveStateKey(db, key, value) {
  const stateValue =
    value === null || value === undefined
      ? null
      : String(value);

  if (stateValue === null) {
    await db
      .prepare(
        "DELETE FROM site_state WHERE state_key = ?"
      )
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


// ========================================
// ELIMINAR MENSAJES DE MÁS DE 3 DÍAS
// ========================================

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
