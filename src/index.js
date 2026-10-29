export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const json = (data, status = 200, headers = {}) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          ...headers
        }
      });

    const clean = v => String(v ?? "").trim();
    const safeName = v =>
      clean(v)
        .replace(/[^\w.\- áéíóúÁÉÍÓÚñÑ()]/g, "_")
        .replace(/\s+/g, "_")
        .slice(0, 150) || "archivo";

    const cookieName = "bbang_admin";

    function b64url(bytes) {
      let s = "";
      for (const b of bytes) s += String.fromCharCode(b);
      return btoa(s)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
    }

    async function signature(expiry, secret) {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );

      return b64url(
        new Uint8Array(
          await crypto.subtle.sign(
            "HMAC",
            key,
            new TextEncoder().encode(String(expiry))
          )
        )
      );
    }

    async function isAdmin(req) {
      const secret = clean(env.INSTYLE_ADMIN_SECRET);
      if (!secret) return false;

      const match = (req.headers.get("Cookie") || "")
        .match(/(?:^|;\s*)bbang_admin=([^;]+)/);

      if (!match) return false;

      const parts = match[1].split(".");
      const expiry = Number(parts[0]);

      if (
        parts.length !== 2 ||
        !Number.isSafeInteger(expiry) ||
        expiry <= Math.floor(Date.now() / 1000)
      ) {
        return false;
      }

      try {
        return parts[1] === await signature(expiry, secret);
      } catch {
        return false;
      }
    }

    async function deleteAttachments(row) {
      let files = [];

      try {
        const parsed = JSON.parse(row?.attachment_name || "[]");
        if (Array.isArray(parsed)) files = parsed;
      } catch {}

      for (const file of files) {
        if (file?.key) {
          try {
            await env.MESSAGE_FILES?.delete(file.key);
          } catch {}
        }
      }
    }

    async function cleanupOldMessages() {
      const cutoff = new Date(
        Date.now() - 7 * 86400000
      ).toISOString();

      const result = await env.DB
        .prepare(
          "SELECT id, attachment_name FROM messages WHERE created_at < ?"
        )
        .bind(cutoff)
        .all();

      let deleted = 0;

      for (const row of result.results || []) {
        await deleteAttachments(row);

        await env.DB
          .prepare("DELETE FROM messages WHERE id = ?")
          .bind(row.id)
          .run();

        deleted++;
      }

      return deleted;
    }

    // ACCESO DE ADMINISTRADOR

    if (url.pathname === "/api/admin-login") {
      if (request.method !== "POST") {
        return json({ message: "Método no permitido." }, 405);
      }

      try {
        const body = await request.json();
        const secret = clean(env.INSTYLE_ADMIN_SECRET);

        if (!secret || clean(body?.code) !== secret) {
          return json(
            { ok: false, message: "Clave incorrecta." },
            401
          );
        }

        const expiry = Math.floor(Date.now() / 1000) + 86400;
        const sig = await signature(expiry, secret);

        return json(
          { ok: true },
          200,
          {
            "Set-Cookie":
              `${cookieName}=${expiry}.${sig}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`
          }
        );
      } catch (e) {
        console.error("ERROR /api/admin-login", e);
        return json({ message: "Solicitud inválida." }, 400);
      }
    }

    if (url.pathname === "/api/admin-status") {
      if (request.method !== "GET") {
        return json({ message: "Método no permitido." }, 405);
      }

      const ok = await isAdmin(request);
      return json({ ok }, ok ? 200 : 401);
    }

    if (url.pathname === "/api/admin-logout") {
      return json(
        { ok: true },
        200,
        {
          "Set-Cookie":
            `${cookieName}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
        }
      );
    }


// VOTACIONES DE LA COMUNIDAD — CONTEO PERSISTENTE EN D1

if (url.pathname === "/api/community-votes") {

  try {

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS community_votes (
        voting_id TEXT NOT NULL,
        option_index INTEGER NOT NULL,
        votes INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (voting_id, option_index)
      )
    `).run();

    // ============================
    // CARGAR VOTOS
    // ============================

    if (request.method === "GET") {

      const ids = clean(
        url.searchParams.get("ids")
      )
        .split(",")
        .map(x => clean(x))
        .filter(Boolean)
        .slice(0, 50);

      if (!ids.length) {
        return json({
          ok: true,
          votes: {}
        });
      }

      const placeholders =
        ids.map(() => "?").join(",");

      const rows = await env.DB
        .prepare(`
          SELECT
            voting_id,
            option_index,
            votes
          FROM community_votes
          WHERE voting_id IN (${placeholders})
        `)
        .bind(...ids)
        .all();

      const votes = {};

      for (const row of rows.results || []) {

        if (!votes[row.voting_id]) {
          votes[row.voting_id] = {};
        }

        votes[row.voting_id][
          String(row.option_index)
        ] = Number(row.votes || 0);
      }

      return json({
        ok: true,
        votes
      });
    }

    // ============================
    // REGISTRAR VOTO
    // ============================

    if (request.method === "POST") {

      const body = await request.json();

      const votingId =
        clean(body?.votingId);

      const optionIndex =
        Number(body?.optionIndex);

      if (
        !votingId ||
        !Number.isInteger(optionIndex) ||
        optionIndex < 0
      ) {
        return json(
          {
            message: "Voto inválido."
          },
          400
        );
      }

      // Buscar la votación guardada
      // en site_state

      const stateRow = await env.DB
        .prepare(
          "SELECT value FROM site_state WHERE key = ?"
        )
        .bind("instyleVotingsV1")
        .first();

      if (!stateRow?.value) {

        return json(
          {
            message:
              "La votación no existe."
          },
          404
        );
      }

      let votaciones = [];

      try {

        votaciones =
          JSON.parse(stateRow.value);

        if (!Array.isArray(votaciones)) {
          votaciones = [];
        }

      } catch {

        votaciones = [];

      }

      const voting =
        votaciones.find(function(item) {

          return (
            item &&
            String(item.id) === votingId &&
            item.type === "instyle"
          );

        });

      if (!voting) {

        return json(
          {
            message:
              "La votación no existe."
          },
          404
        );
      }

      // Verificar que siga activa

      const active =
        voting.status === "active" ||
        voting.active === true ||
        !voting.status;

      if (!active) {

        return json(
          {
            message:
              "Esta votación ya no está activa."
          },
          400
        );
      }

      // Verificar opción

      if (
        !Array.isArray(voting.options) ||
        optionIndex >= voting.options.length
      ) {

        return json(
          {
            message:
              "La opción elegida no es válida."
          },
          400
        );
      }

      const updatedAt =
        new Date().toISOString();

      // Incrementar voto

      await env.DB
        .prepare(`
          INSERT INTO community_votes (
            voting_id,
            option_index,
            votes,
            updated_at
          )
          VALUES (?, ?, 1, ?)

          ON CONFLICT(
            voting_id,
            option_index
          )

          DO UPDATE SET
            votes =
              community_votes.votes + 1,
            updated_at =
              excluded.updated_at
        `)
        .bind(
          votingId,
          optionIndex,
          updatedAt
        )
        .run();

      // Obtener contador actualizado

      const row = await env.DB
        .prepare(`
          SELECT votes
          FROM community_votes
          WHERE voting_id = ?
          AND option_index = ?
        `)
        .bind(
          votingId,
          optionIndex
        )
        .first();

      return json({
        ok: true,
        votingId,
        optionIndex,
        count: Number(
          row?.votes || 0
        )
      });
    }

    return json(
      {
        message:
          "Método no permitido."
      },
      405
    );

  } catch (e) {

    console.error(
      "ERROR /api/community-votes",
      e
    );

    return json(
      {
        ok: false,
        message:
          "No se pudo registrar el voto.",
        error:
          String(e?.message || e)
      },
      500
    );
  }
}
    
    // ESTADO Y CONTENIDO EDITABLE DEL SITIO

    if (url.pathname === "/api/state") {
      if (request.method === "GET") {
        try {
          const rows = await env.DB
            .prepare("SELECT key, value FROM site_state")
            .all();

          const state = {};

          for (const row of rows.results || []) {
            state[row.key] = row.value;
          }

          return json({ ok: true, state });
        } catch (e) {
          console.error("ERROR /api/state GET", e);
          return json(
            { message: "No se pudo cargar el estado del sitio." },
            500
          );
        }
      }

      if (request.method !== "POST") {
        return json({ message: "Método no permitido." }, 405);
      }

      if (!(await isAdmin(request))) {
        return json({ message: "No autorizado." }, 401);
      }

      try {
        const body = await request.json();

        if (
          body?.state &&
          typeof body.state === "object" &&
          !Array.isArray(body.state)
        ) {
          const entries = Object.entries(body.state);

          for (const [key, value] of entries) {
            if (!key) continue;

            await env.DB
              .prepare(`
                INSERT INTO site_state (key, value)
                VALUES (?, ?)
                ON CONFLICT(key)
                DO UPDATE SET value = excluded.value
              `)
              .bind(key, value == null ? null : String(value))
              .run();
          }

          return json({ ok: true, saved: entries.length });
        }

        const key = clean(body?.key);
        const value = body?.value ?? null;

        if (!key) {
          return json(
            { message: "No se recibió ningún estado para guardar." },
            400
          );
        }

        if (value === null) {
          await env.DB
            .prepare("DELETE FROM site_state WHERE key = ?")
            .bind(key)
            .run();
        } else {
          await env.DB
            .prepare(`
              INSERT INTO site_state (key, value)
              VALUES (?, ?)
              ON CONFLICT(key)
              DO UPDATE SET value = excluded.value
            `)
            .bind(key, String(value))
            .run();
        }

        return json({ ok: true, key });
      } catch (e) {
        console.error("ERROR /api/state POST", e);
        return json(
          { message: "No se pudo guardar el estado." },
          500
        );
      }
    }

    // ARCHIVOS DEL SITIO

    if (url.pathname === "/api/site-file") {
      if (request.method === "POST") {
        if (!(await isAdmin(request))) {
          return json({ message: "No autorizado." }, 401);
        }

        if (!env.MESSAGE_FILES) {
          return json(
            {
              message:
                "No está configurado el almacenamiento MESSAGE_FILES."
            },
            500
          );
        }

        try {
          const form = await request.formData();
          const file = form.get("file");
          const prefix = clean(form.get("prefix") || "site");

          if (!file || typeof file.arrayBuffer !== "function") {
            return json({ message: "No se recibió ningún archivo." }, 400);
          }

          if (file.size > 8 * 1024 * 1024) {
            return json(
              { message: "El archivo es demasiado pesado. Máximo 8 MB." },
              400
            );
          }

          const type = clean(file.type) || "application/octet-stream";

          const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            "image/avif",
            "application/pdf",
            "text/plain"
          ];

          if (!allowedTypes.includes(type)) {
            return json({ message: "Tipo de archivo no permitido." }, 400);
          }

          const safePrefix =
            prefix.replace(/[^\w-]/g, "_").slice(0, 50) || "site";

          const name = safeName(file.name || "archivo");

          const key =
            `site/${safePrefix}/${Date.now()}-${crypto.randomUUID()}-${name}`;

          await env.MESSAGE_FILES.put(
            key,
            await file.arrayBuffer(),
            {
              metadata: {
                contentType: type,
                originalName: name
              }
            }
          );

          return json({
            ok: true,
            key,
            url: new URL(
              "/api/site-file?key=" + encodeURIComponent(key),
              request.url
            ).href
          });
        } catch (e) {
          console.error("ERROR /api/site-file POST", e);
          return json(
            { message: "No se pudo guardar el archivo." },
            500
          );
        }
      }

      if (request.method === "GET") {
        try {
          const key = clean(url.searchParams.get("key"));

          if (!key.startsWith("site/")) {
            return new Response("Archivo inválido.", { status: 400 });
          }

          const result = await env.MESSAGE_FILES.getWithMetadata(
            key,
            { type: "arrayBuffer" }
          );

          if (!result || result.value === null) {
            return new Response("Archivo no encontrado.", { status: 404 });
          }

          return new Response(result.value, {
            headers: {
              "Content-Type":
                result.metadata?.contentType || "application/octet-stream",
              "Cache-Control": "public, max-age=31536000",
              "Content-Disposition": "inline"
            }
          });
        } catch (e) {
          console.error("ERROR /api/site-file GET", e);
          return new Response("No se pudo abrir el archivo.", { status: 500 });
        }
      }

      return json({ message: "Método no permitido." }, 405);
    }

    // DESCARGA DE ARCHIVOS ADJUNTOS A LOS MENSAJES

    if (url.pathname === "/api/message-file") {
      if (request.method !== "GET") {
        return json({ message: "Método no permitido." }, 405);
      }

      if (!(await isAdmin(request))) {
        return json({ message: "No autorizado." }, 401);
      }

      try {
        const id = Number(url.searchParams.get("message"));
        const index = Number(url.searchParams.get("file"));

        if (
          !Number.isInteger(id) ||
          id <= 0 ||
          !Number.isInteger(index) ||
          index < 0
        ) {
          return json({ message: "Archivo inválido." }, 400);
        }

        const row = await env.DB
          .prepare("SELECT attachment_name FROM messages WHERE id = ?")
          .bind(id)
          .first();

        if (!row) {
          return json({ message: "Mensaje no encontrado." }, 404);
        }

        let files = [];

        try {
          const parsed = JSON.parse(row.attachment_name || "[]");
          if (Array.isArray(parsed)) files = parsed;
        } catch {}

        const file = files[index];

        if (!file?.key) {
          return json({ message: "Archivo no encontrado." }, 404);
        }

        const data = await env.MESSAGE_FILES.get(
          file.key,
          { type: "arrayBuffer" }
        );

        if (!data) {
          return json(
            { message: "El archivo ya no está disponible." },
            404
          );
        }

        return new Response(data, {
          headers: {
            "Content-Type": file.type || "application/octet-stream",
            "Content-Length": String(file.size || data.byteLength),
            "Content-Disposition":
              `attachment; filename="${safeName(file.name || "archivo")}"`,
            "Cache-Control": "private, no-store"
          }
        });
      } catch (e) {
        console.error("ERROR /api/message-file", e);
        return json(
          { message: "No se pudo abrir el archivo." },
          500
        );
      }
    }

    // MENSAJES DE LOS VISITANTES

    if (url.pathname === "/api/messages") {
      if (request.method === "POST") {
        const savedKeys = [];

        try {
          const form = await request.formData();

          const category = clean(
            form.get("category") ||
            form.get("motivo") ||
            form.get("categoria") ||
            form.get("reason")
          );

          const name = clean(
            form.get("name") || form.get("nombre")
          );

          const email = clean(
            form.get("email") || form.get("correo")
          );

          const description = clean(
            form.get("description") ||
            form.get("descripcion") ||
            form.get("mensaje")
          );

          if (clean(form.get("website"))) {
            return json({ ok: true });
          }

          if (!category) {
            return json({ message: "Seleccioná una categoría." }, 400);
          }

          if (!description) {
            return json({ message: "Escribí el mensaje." }, 400);
          }

          if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return json(
              { message: "El correo electrónico no es válido." },
              400
            );
          }

          const id = Date.now();
          const attachments = [];

          for (const file of form.getAll("files")) {
            if (
              !file ||
              typeof file.arrayBuffer !== "function" ||
              !file.size
            ) {
              continue;
            }

            if (file.size > 8 * 1024 * 1024) {
              return json(
                {
                  message:
                    "Uno de los archivos supera el límite de 8 MB."
                },
                400
              );
            }

            const type = clean(file.type) || "application/octet-stream";
            const filename = safeName(file.name || "archivo");

            const key =
              `messages/${id}/${Date.now()}-${crypto.randomUUID()}-${filename}`;

            await env.MESSAGE_FILES.put(
              key,
              await file.arrayBuffer(),
              {
                metadata: {
                  contentType: type,
                  originalName: filename
                }
              }
            );

            savedKeys.push(key);

            attachments.push({
              name: filename,
              type,
              size: file.size,
              key
            });
          }

          await env.DB
            .prepare(`
              INSERT INTO messages (
                id,
                category,
                name,
                email,
                description,
                attachment_name,
                attachment_type,
                attachment_size,
                created_at
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `)
            .bind(
              id,
              category,
              name,
              email,
              description,
              JSON.stringify(attachments),
              attachments[0]?.type || null,
              attachments[0]?.size || null,
              new Date().toISOString()
            )
            .run();

          return json({ ok: true, id });
        } catch (e) {
          for (const key of savedKeys) {
            try {
              await env.MESSAGE_FILES?.delete(key);
            } catch {}
          }

          console.error("ERROR /api/messages POST", e);

          return json(
            { message: "No se pudo enviar el mensaje." },
            500
          );
        }
      }

      if (request.method === "GET") {
        if (!(await isAdmin(request))) {
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

          const messages = (rows.results || []).map(row => {
            let attachments = [];

            try {
              const parsed = JSON.parse(row.attachment_name || "[]");
              if (Array.isArray(parsed)) attachments = parsed;
            } catch {}

            return { ...row, attachments };
          });

          return json({ messages });
        } catch (e) {
          console.error("ERROR /api/messages GET", e);

          return json(
            { message: "No se pudieron cargar los mensajes." },
            500
          );
        }
      }

      if (request.method === "DELETE") {
        if (!(await isAdmin(request))) {
          return json({ message: "No autorizado." }, 401);
        }

        try {
          const body = await request.json();
          const id = Number(body.id);

          if (!Number.isInteger(id) || id <= 0) {
            return json({ message: "ID de mensaje inválido." }, 400);
          }

          const row = await env.DB
            .prepare("SELECT attachment_name FROM messages WHERE id = ?")
            .bind(id)
            .first();

          if (row) await deleteAttachments(row);

          await env.DB
            .prepare("DELETE FROM messages WHERE id = ?")
            .bind(id)
            .run();

          return json({ ok: true });
        } catch (e) {
          console.error("ERROR /api/messages DELETE", e);

          return json(
            { message: "No se pudo eliminar el mensaje." },
            500
          );
        }
      }

      return json({ message: "Método no permitido." }, 405);
    }

    // LIMPIEZA MANUAL DE MENSAJES ANTIGUOS

    if (url.pathname === "/api/cleanup-messages") {
      if (!(await isAdmin(request))) {
        return json({ message: "No autorizado." }, 401);
      }

      try {
        return json({
          ok: true,
          deleted: await cleanupOldMessages()
        });
      } catch (e) {
        console.error("ERROR /api/cleanup-messages", e);

        return json(
          { message: "No se pudo realizar la limpieza." },
          500
        );
      }
    }

    // ARCHIVOS ESTÁTICOS DE LA PÁGINA

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Bbang-Hola", {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=UTF-8"
      }
    });
  },

  // LIMPIEZA AUTOMÁTICA SEMANAL

  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        const cutoff = new Date(
          Date.now() - 7 * 86400000
        ).toISOString();

        const result = await env.DB
          .prepare(
            "SELECT id, attachment_name FROM messages WHERE created_at < ?"
          )
          .bind(cutoff)
          .all();

        for (const row of result.results || []) {
          let files = [];

          try {
            const parsed = JSON.parse(row.attachment_name || "[]");
            if (Array.isArray(parsed)) files = parsed;
          } catch {}

          for (const file of files) {
            if (file?.key) {
              try {
                await env.MESSAGE_FILES?.delete(file.key);
              } catch {}
            }
          }

          await env.DB
            .prepare("DELETE FROM messages WHERE id = ?")
            .bind(row.id)
            .run();
        }
      } catch (e) {
        console.error("ERROR limpieza semanal", e);
      }
    })());
  }
};
