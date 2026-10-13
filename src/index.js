export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // =========================
    // FUNCIONES GENERALES
    // =========================

    const json = (data, status = 200, extraHeaders = {}) =>
      new Response(JSON.stringify(data), {
        status,
        headers: {
          "content-type": "application/json; charset=UTF-8",
          ...extraHeaders
        }
      });

    const clean = (value) =>
      String(value ?? "").trim();

    const sanitizeFileName = (name) =>
      clean(name)
        .replace(/[^\w.\- áéíóúÁÉÍÓÚñÑ()]/g, "_")
        .replace(/\s+/g, "_")
        .slice(0, 150) || "archivo";

    const ADMIN_CODE = "INSTYLE2026";

    function isAdmin(request, env) {
      const headerCode =
        request.headers.get("X-INSTYLE-ADMIN") || "";

      if (headerCode === ADMIN_CODE) {
        return true;
      }

      const cookie =
        request.headers.get("Cookie") || "";

      const match =
        cookie.match(/instyle_admin=([^;]+)/);

      if (match && match[1] === "1") {
        return true;
      }

      return false;
    }

    // =========================
    // LOGIN ADMIN
    // =========================

    if (url.pathname === "/api/admin-login") {
      if (request.method !== "POST") {
        return json(
          { message: "Método no permitido." },
          405
        );
      }

      try {
        const body = await request.json();
        const code = clean(body?.code);

        const configuredSecret =
          env.INSTYLE_ADMIN_SECRET
            ? String(env.INSTYLE_ADMIN_SECRET)
            : "";

        const valid =
          code === ADMIN_CODE ||
          (configuredSecret && code === configuredSecret);

        if (!valid) {
          return json(
            { ok: false, message: "Clave incorrecta." },
            401
          );
        }

        return json(
          { ok: true },
          200,
          {
            "Set-Cookie":
              "instyle_admin=1; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400"
          }
        );
      } catch (error) {
        return json(
          { message: "Solicitud inválida." },
          400
        );
      }
    }

    // =========================
    // LOGOUT ADMIN
    // =========================

    if (url.pathname === "/api/admin-logout") {
      return json(
        { ok: true },
        200,
        {
          "Set-Cookie":
            "instyle_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
        }
      );
    }

    // =========================
    // ESTADO DEL SITIO — D1
    // =========================

    if (url.pathname === "/api/state") {

      if (request.method === "GET") {
        try {
          const rows = await env.DB
            .prepare(`
              SELECT key, value
              FROM site_state
            `)
            .all();

          const state = {};

          for (const row of rows.results || []) {
            state[row.key] = row.value;
          }

          return json({
            ok: true,
            state
          });
        } catch (error) {
          return json(
            {
              message:
                "No se pudo cargar el estado del sitio."
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

          const state =
            body &&
            body.state &&
            typeof body.state === "object"
              ? body.state
              : null;

          const key =
            clean(body?.key);

          const value =
            body?.value ?? null;

          if (state) {
            const entries =
              Object.entries(state);

            for (const [stateKey, stateValue] of entries) {

              if (!stateKey) continue;

              await env.DB
                .prepare(`
                  INSERT INTO site_state (key, value)
                  VALUES (?, ?)
                  ON CONFLICT(key)
                  DO UPDATE SET value = excluded.value
                `)
                .bind(
                  stateKey,
                  stateValue == null
                    ? null
                    : String(stateValue)
                )
                .run();
            }

            return json({
              ok: true,
              saved: entries.length
            });
          }

          if (key) {

            if (value === null) {
              await env.DB
                .prepare(`
                  DELETE FROM site_state
                  WHERE key = ?
                `)
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
                .bind(
                  key,
                  String(value)
                )
                .run();
            }

            return json({
              ok: true,
              key
            });
          }

          return json(
            {
              message:
                "No se recibió ningún estado para guardar."
            },
            400
          );

        } catch (error) {
          return json(
            {
              message:
                "No se pudo guardar el estado."
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
    //
    // IMPORTANTE:
    // MESSAGE_FILES = KV
    // NO R2
    // =========================

    if (url.pathname === "/api/site-file") {

      // -------------------------
      // SUBIR IMAGEN / ARCHIVO
      // -------------------------

      if (request.method === "POST") {

        if (!isAdmin(request, env)) {
          return json(
            { message: "No autorizado." },
            401
          );
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

          const form =
            await request.formData();

          const file =
            form.get("file");

          const prefix =
            clean(form.get("prefix") || "site");

          if (
            !file ||
            typeof file !== "object" ||
            typeof file.arrayBuffer !== "function"
          ) {
            return json(
              {
                message:
                  "No se recibió ningún archivo."
              },
              400
            );
          }

          const maxBytes =
            8 * 1024 * 1024;

          if (file.size > maxBytes) {
            return json(
              {
                message:
                  "El archivo es demasiado pesado. Máximo 8 MB."
              },
              400
            );
          }

          const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            "image/avif",
            "application/pdf",
            "text/plain"
          ];

          const type =
            clean(file.type) ||
            "application/octet-stream";

          if (!allowedTypes.includes(type)) {
            return json(
              {
                message:
                  "Tipo de archivo no permitido."
              },
              400
            );
          }

          const safePrefix =
            prefix
              .replace(/[^\w\-]/g, "_")
              .slice(0, 50) ||
            "site";

          const safeName =
            sanitizeFileName(
              file.name || "archivo"
            );

          const randomPart =
            crypto.randomUUID();

          const key =
            `site/${safePrefix}/${Date.now()}-${randomPart}-${safeName}`;

          // KV:
          // guardamos el archivo junto con su
          // Content-Type como metadata.
          await env.MESSAGE_FILES.put(
            key,
            await file.arrayBuffer(),
            {
              metadata: {
                contentType: type,
                originalName: safeName
              }
            }
          );

          const fileUrl =
            new URL(
              "/api/site-file?key=" +
                encodeURIComponent(key),
              request.url
            ).href;

          return json({
            ok: true,
            key,
            url: fileUrl
          });

        } catch (error) {

          console.error(
            "ERROR /api/site-file POST:",
            error
          );

          return json(
            {
              message:
                "No se pudo guardar el archivo."
            },
            500
          );
        }
      }

      // -------------------------
      // MOSTRAR IMAGEN / ARCHIVO
      // -------------------------

      if (request.method === "GET") {

        try {

          const key =
            clean(
              url.searchParams.get("key")
            );

          if (!key) {
            return new Response(
              "Archivo inválido.",
              { status: 400 }
            );
          }

          // Seguridad:
          // solamente permitimos archivos
          // pertenecientes al sitio.
          if (!key.startsWith("site/")) {
            return new Response(
              "Archivo inválido.",
              { status: 400 }
            );
          }

          const result =
            await env.MESSAGE_FILES.getWithMetadata(
              key,
              {
                type: "arrayBuffer"
              }
            );

          if (
            !result ||
            result.value === null
          ) {
            return new Response(
              "Archivo no encontrado.",
              { status: 404 }
            );
          }

          const metadata =
            result.metadata || {};

          const contentType =
            metadata.contentType ||
            "application/octet-stream";

          const headers =
            new Headers();

          headers.set(
            "Content-Type",
            String(contentType)
          );

          headers.set(
            "Cache-Control",
            "public, max-age=31536000"
          );

          headers.set(
            "Content-Disposition",
            "inline"
          );

          return new Response(
            result.value,
            {
              status: 200,
              headers
            }
          );

        } catch (error) {

          console.error(
            "ERROR /api/site-file GET:",
            error
          );

          return new Response(
            "No se pudo abrir el archivo.",
            { status: 500 }
          );
        }
      }

      return json(
        { message: "Método no permitido." },
        405
      );
    }

    // =========================
    // DESCARGAR ARCHIVO DE MENSAJE
    // =========================

    if (url.pathname === "/api/message-file") {

      if (request.method !== "GET") {
        return json(
          { message: "Método no permitido." },
          405
        );
      }

      if (!isAdmin(request, env)) {
        return json(
          { message: "No autorizado." },
          401
        );
      }

      try {

        const messageId =
          Number(
            url.searchParams.get("message")
          );

        const fileIndex =
          Number(
            url.searchParams.get("file")
          );

        if (
          !Number.isInteger(messageId) ||
          messageId <= 0 ||
          !Number.isInteger(fileIndex) ||
          fileIndex < 0
        ) {
          return json(
            { message: "Archivo inválido." },
            400
          );
        }

        const row =
          await env.DB
            .prepare(`
              SELECT attachment_name
              FROM messages
              WHERE id = ?
            `)
            .bind(messageId)
            .first();

        if (!row) {
          return json(
            {
              message:
                "Mensaje no encontrado."
            },
            404
          );
        }

        let files = [];

        try {
          const parsed =
            JSON.parse(
              row.attachment_name || "[]"
            );

          files =
            Array.isArray(parsed)
              ? parsed
              : [];
        } catch (error) {
          files = [];
        }

        const file =
          files[fileIndex];

        if (!file || !file.key) {
          return json(
            {
              message:
                "Archivo no encontrado."
            },
            404
          );
        }

        const storedFile =
          await env.MESSAGE_FILES.get(
            file.key,
            {
              type: "arrayBuffer"
            }
          );

        if (!storedFile) {
          return json(
            {
              message:
                "El archivo ya no está disponible."
            },
            404
          );
        }

        const safeName =
          sanitizeFileName(
            file.name || "archivo"
          );

        return new Response(
          storedFile,
          {
            status: 200,
            headers: {
              "Content-Type":
                file.type ||
                "application/octet-stream",

              "Content-Length":
                String(
                  file.size ||
                  storedFile.byteLength
                ),

              "Content-Disposition":
                `attachment; filename="${safeName}"`,

              "Cache-Control":
                "private, no-store"
            }
          }
        );

      } catch (error) {

        console.error(
          "ERROR /api/message-file:",
          error
        );

        return json(
          {
            message:
              "No se pudo abrir el archivo."
          },
          500
        );
      }
    }

    // =========================
    // MENSAJES
    // =========================

    if (url.pathname === "/api/messages") {

      // -------------------------
      // RECIBIR MENSAJE
      // -------------------------

      if (request.method === "POST") {

        try {

          const form =
            await request.formData();

          const category =
            clean(
              form.get("category") ||
              form.get("motivo") ||
              form.get("categoria") ||
              form.get("reason")
            );

          const name =
            clean(
              form.get("name") ||
              form.get("nombre")
            );

          const email =
            clean(
              form.get("email") ||
              form.get("correo")
            );

          const description =
            clean(
              form.get("description") ||
              form.get("descripcion") ||
              form.get("mensaje")
            );

          const honeypot =
            clean(
              form.get("website")
            );

          if (honeypot) {
            return json({ ok: true });
          }

          if (!category) {
            return json(
              {
                message:
                  "Seleccioná una categoría."
              },
              400
            );
          }

          if (!description) {
            return json(
              {
                message:
                  "Escribí el mensaje."
              },
              400
            );
          }

          if (
            email &&
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
          ) {
            return json(
              {
                message:
                  "El correo electrónico no es válido."
              },
              400
            );
          }

          const messageId =
            Date.now();

          const attachments = [];

          for (const item of form.getAll("files")) {

            if (
              !item ||
              typeof item !== "object" ||
              typeof item.arrayBuffer !== "function"
            ) {
              continue;
            }

            if (!item.size) {
              continue;
            }

            const maxBytes =
              8 * 1024 * 1024;

            if (item.size > maxBytes) {
              return json(
                {
                  message:
                    "Uno de los archivos supera el límite de 8 MB."
                },
                400
              );
            }

            const type =
              clean(item.type) ||
              "application/octet-stream";

            const safeName =
              sanitizeFileName(
                item.name || "archivo"
              );

            const key =
              `messages/${messageId}/${Date.now()}-${crypto.randomUUID()}-${safeName}`;

            await env.MESSAGE_FILES.put(
              key,
              await item.arrayBuffer(),
              {
                metadata: {
                  contentType: type,
                  originalName: safeName
                }
              }
            );

            attachments.push({
              name: safeName,
              type,
              size: item.size,
              key
            });
          }

          await env.DB
            .prepare(`
              INSERT INTO messages
              (
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
              messageId,
              category,
              name,
              email,
              description,
              JSON.stringify(attachments),
              attachments.length
                ? attachments[0].type
                : null,
              attachments.length
                ? attachments[0].size
                : null,
              new Date().toISOString()
            )
            .run();

          return json({
            ok: true,
            id: messageId
          });

        } catch (error) {

          console.error(
            "ERROR /api/messages POST:",
            error
          );

          return json(
            {
              message:
                "No se pudo enviar el mensaje."
            },
            500
          );
        }
      }

      // -------------------------
      // CONSULTAR MENSAJES
      // -------------------------

      if (request.method === "GET") {

        if (!isAdmin(request, env)) {
          return json(
            { message: "No autorizado." },
            401
          );
        }

        try {

          const rows =
            await env.DB
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

          const messages =
            (rows.results || []).map(
              row => {

                let attachments = [];

                try {
                  const parsed =
                    JSON.parse(
                      row.attachment_name || "[]"
                    );

                  attachments =
                    Array.isArray(parsed)
                      ? parsed
                      : [];
                } catch (error) {
                  attachments = [];
                }

                return {
                  ...row,
                  attachments
                };
              }
            );

          return json({
            messages
          });

        } catch (error) {

          console.error(
            "ERROR /api/messages GET:",
            error
          );

          return json(
            {
              message:
                "No se pudieron cargar los mensajes."
            },
            500
          );
        }
      }

      // -------------------------
      // ELIMINAR MENSAJE
      // -------------------------

      if (request.method === "DELETE") {

        if (!isAdmin(request, env)) {
          return json(
            { message: "No autorizado." },
            401
          );
        }

        try {

          const body =
            await request.json();

          const id =
            Number(body.id);

          if (
            !Number.isInteger(id) ||
            id <= 0
          ) {
            return json(
              {
                message:
                  "ID de mensaje inválido."
              },
              400
            );
          }

          const row =
            await env.DB
              .prepare(`
                SELECT attachment_name
                FROM messages
                WHERE id = ?
              `)
              .bind(id)
              .first();

          if (row) {

            let files = [];

            try {
              const parsed =
                JSON.parse(
                  row.attachment_name || "[]"
                );

              files =
                Array.isArray(parsed)
                  ? parsed
                  : [];
            } catch (error) {
              files = [];
            }

            for (const file of files) {

              if (!file?.key) {
                continue;
              }

              try {
                await env.MESSAGE_FILES.delete(
                  file.key
                );
              } catch (error) {}
            }
          }

          await env.DB
            .prepare(
              "DELETE FROM messages WHERE id = ?"
            )
            .bind(id)
            .run();

          return json({
            ok: true
          });

        } catch (error) {

          console.error(
            "ERROR /api/messages DELETE:",
            error
          );

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
        {
          message:
            "Método no permitido."
        },
        405
      );
    }

    // =========================
    // LIMPIEZA DE MENSAJES
    // =========================

    if (
      url.pathname === "/api/cleanup-messages"
    ) {

      if (!isAdmin(request, env)) {
        return json(
          { message: "No autorizado." },
          401
        );
      }

      try {

        const cutoff =
          new Date(
            Date.now() -
              7 * 24 * 60 * 60 * 1000
          ).toISOString();

        const rows =
          await env.DB
            .prepare(`
              SELECT
                id,
                attachment_name
              FROM messages
              WHERE created_at < ?
            `)
            .bind(cutoff)
            .all();

        let deleted =
          0;

        for (
          const row
          of rows.results || []
        ) {

          let files = [];

          try {
            const parsed =
              JSON.parse(
                row.attachment_name || "[]"
              );

            files =
              Array.isArray(parsed)
                ? parsed
                : [];
          } catch (error) {
            files = [];
          }

          for (const file of files) {

            if (!file?.key) {
              continue;
            }

            try {
              await env.MESSAGE_FILES.delete(
                file.key
              );
            } catch (error) {}
          }

          await env.DB
            .prepare(
              "DELETE FROM messages WHERE id = ?"
            )
            .bind(row.id)
            .run();

          deleted++;
        }

        return json({
          ok: true,
          deleted
        });

      } catch (error) {

        console.error(
          "ERROR /api/cleanup-messages:",
          error
        );

        return json(
          {
            message:
              "No se pudo realizar la limpieza."
          },
          500
        );
      }
    }

    // =========================
    // ARCHIVOS DEL SITIO
    // =========================

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response(
      "FAN - I.N",
      {
        status: 200,
        headers: {
          "content-type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  },

  // =========================
  // CRON
  // =========================

  async scheduled(event, env, ctx) {

    ctx.waitUntil(
      (async () => {

        try {

          const cutoff =
            new Date(
              Date.now() -
                7 * 24 * 60 * 60 * 1000
            ).toISOString();

          const rows =
            await env.DB
              .prepare(`
                SELECT
                  id,
                  attachment_name
                FROM messages
                WHERE created_at < ?
              `)
              .bind(cutoff)
              .all();

          for (
            const row
            of rows.results || []
          ) {

            let files = [];

            try {
              const parsed =
                JSON.parse(
                  row.attachment_name || "[]"
                );

              files =
                Array.isArray(parsed)
                  ? parsed
                  : [];
            } catch (error) {
              files = [];
            }

            for (const file of files) {

              if (!file?.key) {
                continue;
              }

              try {
                await env.MESSAGE_FILES.delete(
                  file.key
                );
              } catch (error) {}
            }

            await env.DB
              .prepare(
                "DELETE FROM messages WHERE id = ?"
              )
              .bind(row.id)
              .run();
          }

        } catch (error) {
          console.error(
            "ERROR limpieza semanal:",
            error
          );
        }

      })()
    );
  }
};
