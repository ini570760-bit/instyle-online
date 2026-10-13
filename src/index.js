export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    /* =========================================================
       LOGIN ADMIN
    ========================================================= */

    if (url.pathname === "/api/admin-login") {
      if (request.method !== "POST") {
        return json({ message: "Método no permitido." }, 405);
      }

      try {
        const body = await request.json();
        const secret = clean(body.secret);

        if (!secret) {
          return json({ message: "Ingresá la clave de administración." }, 400);
        }

        /*
         * La clave verdadera vive en el secreto de Cloudflare:
         * INSTYLE_ADMIN_SECRET
         *
         * También mantenemos compatibilidad con el código
         * que usa actualmente el sitio.
         */
        const valid =
          (env.INSTYLE_ADMIN_SECRET &&
            secret === env.INSTYLE_ADMIN_SECRET) ||
          secret === "INSTYLE2026";

        if (!valid) {
          return json({ message: "Clave incorrecta." }, 401);
        }

        const headers = new Headers({
          "content-type": "application/json; charset=UTF-8",
          "cache-control": "no-store"
        });

        headers.append(
          "Set-Cookie",
          "instyle_admin_session=1; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400"
        );

        return new Response(
          JSON.stringify({
            ok: true,
            message: "Sesión de administradora iniciada."
          }),
          {
            status: 200,
            headers
          }
        );
      } catch (error) {
        console.error("ERROR /api/admin-login:", error);

        return json(
          {
            message:
              "No se pudo iniciar la sesión de administración."
          },
          500
        );
      }
    }


    /* =========================================================
       LOGOUT ADMIN
    ========================================================= */

    if (url.pathname === "/api/admin-logout") {
      const headers = new Headers({
        "content-type": "application/json; charset=UTF-8",
        "cache-control": "no-store"
      });

      headers.append(
        "Set-Cookie",
        "instyle_admin_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0"
      );

      return new Response(
        JSON.stringify({
          ok: true
        }),
        {
          status: 200,
          headers
        }
      );
    }


    /* =========================================================
       ESTADO DEL SITIO
    ========================================================= */

    if (url.pathname === "/api/state") {

      /* ---------- LEER ---------- */

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

          return json({
            state
          });

        } catch (error) {
          console.error("ERROR GET /api/state:", error);

          return json(
            {
              message:
                "No se pudo leer el estado del sitio."
            },
            500
          );
        }
      }


      /* ---------- GUARDAR ---------- */

      if (request.method === "POST") {

        if (!isAdmin(request)) {
          return json(
            {
              message: "No autorizado."
            },
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

            return json({
              ok: true
            });
          }

          if (
            body.state &&
            typeof body.state === "object"
          ) {
            for (const [key, value] of Object.entries(
              body.state
            )) {
              await saveStateKey(
                env.DB,
                key,
                value
              );
            }

            return json({
              ok: true
            });
          }

          return json(
            {
              message: "Estado inválido."
            },
            400
          );

        } catch (error) {
          console.error("ERROR POST /api/state:", error);

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
        {
          message: "Método no permitido."
        },
        405
      );
    }


    /* =========================================================
       ARCHIVOS DEL SITIO
       
       Sirve para:
       - Instagram
       - Promoción
       - Tutoriales
       - Fan Groups
       - Home
       - cualquier imagen futura
    ========================================================= */

    if (url.pathname === "/api/site-file") {

      /* ---------- SUBIR ---------- */

      if (request.method === "POST") {

        if (!isAdmin(request)) {
          return json(
            {
              message: "No autorizado."
            },
            401
          );
        }

        if (!env.MESSAGE_FILES) {
          return json(
            {
              message:
                "El almacenamiento de archivos no está configurado en Cloudflare."
            },
            500
          );
        }

        try {
          const form = await request.formData();

          const file = form.get("file");
          const prefix =
            clean(form.get("prefix")) || "site";

          if (
            !file ||
            typeof file !== "object" ||
            !("name" in file)
          ) {
            return json(
              {
                message:
                  "No se recibió ningún archivo."
              },
              400
            );
          }

          const size = Number(file.size || 0);

          /*
           * Límite individual para imágenes del sitio.
           */
          if (size > 8 * 1024 * 1024) {
            return json(
              {
                message:
                  "La imagen no puede superar los 8 MB."
              },
              400
            );
          }

          const type =
            String(file.type || "").toLowerCase();

          /*
           * Permitimos imágenes y documentos comunes.
           */
          const allowedTypes = [
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif",
            "image/avif",
            "application/pdf",
            "text/plain"
          ];

          if (
            type &&
            !allowedTypes.includes(type)
          ) {
            return json(
              {
                message:
                  "Tipo de archivo no permitido."
              },
              400
            );
          }

          const safePrefix =
            sanitizePathPart(prefix);

          const safeName =
            sanitizeFileName(file.name);

          const unique =
            Date.now() +
            "-" +
            Math.random()
              .toString(36)
              .slice(2, 10);

          const key =
            "site/" +
            safePrefix +
            "/" +
            unique +
            "-" +
            safeName;

          await env.MESSAGE_FILES.put(
            key,
            file.stream(),
            {
              httpMetadata: {
                contentType:
                  type ||
                  "application/octet-stream",
                cacheControl:
                  "public, max-age=31536000"
              }
            }
          );

          return json({
            ok: true,
            key,
            url:
              "/api/site-file?key=" +
              encodeURIComponent(key)
          });

        } catch (error) {
          console.error(
            "ERROR POST /api/site-file:",
            error
          );

          return json(
            {
              message:
                "No se pudo guardar la imagen.",
              error:
                String(
                  error?.message || error
                )
            },
            500
          );
        }
      }


      /* ---------- MOSTRAR ---------- */

      if (request.method === "GET") {

        if (!env.MESSAGE_FILES) {
          return new Response(
            "Almacenamiento no configurado.",
            {
              status: 500
            }
          );
        }

        try {
          const key =
            url.searchParams.get("key");

          if (!key) {
            return new Response(
              "Archivo no especificado.",
              {
                status: 400
              }
            );
          }

          /*
           * Solo permitimos archivos dentro
           * del espacio site/.
           */
          if (!key.startsWith("site/")) {
            return new Response(
              "Archivo inválido.",
              {
                status: 400
              }
            );
          }

          const object =
            await env.MESSAGE_FILES.get(key);

          if (!object) {
            return new Response(
              "Archivo no encontrado.",
              {
                status: 404
              }
            );
          }

          const headers =
            new Headers();

          object.writeHttpMetadata(
            headers
          );

          headers.set(
            "cache-control",
            "public, max-age=31536000"
          );

          return new Response(
            object.body,
            {
              headers
            }
          );

        } catch (error) {
          console.error(
            "ERROR GET /api/site-file:",
            error
          );

          return new Response(
            "No se pudo abrir el archivo.",
            {
              status: 500
            }
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


    /* =========================================================
       MENSAJES DE VISITANTES
    ========================================================= */

    if (url.pathname === "/api/messages") {

      try {
        await cleanupMessages(env.DB);
      } catch (error) {
        console.error(
          "ERROR limpieza mensajes:",
          error
        );
      }


      /* ---------- RECIBIR MENSAJE ---------- */

      if (request.method === "POST") {

        try {
          const form =
            await request.formData();

          const category =
            clean(
              form.get("category") ||
              form.get("motivo")
            );

          const name =
            clean(
              form.get("name") ||
              form.get("nombre")
            );

          const email =
            clean(
              form.get("email")
            );

          const description =
            clean(
              form.get("description") ||
              form.get("descripcion")
            );

          const honeypot =
            clean(
              form.get("website")
            );

          if (honeypot) {
            return json({
              ok: true
            });
          }

          if (
            !category ||
            !email ||
            !description
          ) {
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
                message:
                  "Ingresá un correo válido."
              },
              400
            );
          }

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


          /* ---------- ARCHIVOS ---------- */

          const files = [];

          for (const [
            fieldName,
            value
          ] of form.entries()) {

            if (
              !fieldName.startsWith(
                "attachment"
              )
            ) {
              continue;
            }

            if (
              !value ||
              typeof value !== "object" ||
              !("name" in value)
            ) {
              continue;
            }

            const size =
              Number(value.size || 0);

            if (!size) continue;

            if (
              !env.MESSAGE_FILES
            ) {
              return json(
                {
                  message:
                    "El almacenamiento de archivos no está configurado."
                },
                500
              );
            }

            if (
              size > 8 * 1024 * 1024
            ) {
              return json(
                {
                  message:
                    "Cada archivo no puede superar los 8 MB."
                },
                400
              );
            }

            files.push({
              originalName:
                String(
                  value.name || "archivo"
                ),
              type:
                String(
                  value.type || ""
                ),
              size,
              file:
                value
            });
          }


          /*
           * Límite total del mensaje:
           * 8 MB.
           */
          const totalSize =
            files.reduce(
              (total, file) =>
                total + file.size,
              0
            );

          if (
            totalSize >
            8 * 1024 * 1024
          ) {
            return json(
              {
                message:
                  "El total de los archivos adjuntos no puede superar los 8 MB."
              },
              400
            );
          }


          /* ---------- CREAR MENSAJE ---------- */

          const createdAt =
            new Date().toISOString();

          const result =
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
                "",
                "",
                totalSize,
                createdAt
              )
              .run();

          const messageId =
            Number(
              result.meta?.last_row_id
            );

          const savedFiles = [];


          /* ---------- GUARDAR ARCHIVOS ---------- */

          for (
            let index = 0;
            index < files.length;
            index++
          ) {

            const item =
              files[index];

            const safeName =
              sanitizeFileName(
                item.originalName
              );

            const key =
              "messages/" +
              messageId +
              "/" +
              Date.now() +
              "-" +
              index +
              "-" +
              safeName;

            await env.MESSAGE_FILES.put(
              key,
              item.file.stream(),
              {
                httpMetadata: {
                  contentType:
                    item.type ||
                    "application/octet-stream"
                }
              }
            );

            savedFiles.push({
              name:
                item.originalName,
              type:
                item.type,
              size:
                item.size,
              key
            });
          }


          /* ---------- ACTUALIZAR DATOS ---------- */

          if (savedFiles.length) {

            await env.DB
              .prepare(`
                UPDATE messages
                SET
                  attachment_name = ?,
                  attachment_type = ?
                WHERE id = ?
              `)
              .bind(
                JSON.stringify(
                  savedFiles
                ),
                "multiple",
                messageId
              )
              .run();
          }


          return json({
            ok: true,
            emailSent: false,
            message:
              "Mensaje recibido. El equipo de I.N STYLE lo verá pronto."
          });

        } catch (error) {

          console.error(
            "ERROR REAL /api/messages:",
            error
          );

          return json(
            {
              message:
                "ERROR REAL: " +
                String(
                  error?.message ||
                  error
                )
            },
            500
          );
        }
      }


      /* ---------- VER MENSAJES ---------- */

      if (request.method === "GET") {

        if (!isAdmin(request)) {
          return json(
            {
              message:
                "No autorizado."
            },
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
            (rows.results || [])
              .map(message => {

                let attachments = [];

                if (
                  message.attachment_name
                ) {
                  try {

                    const parsed =
                      JSON.parse(
                        message.attachment_name
                      );

                    if (
                      Array.isArray(
                        parsed
                      )
                    ) {
                      attachments =
                        parsed;
                    }

                  } catch (error) {

                    attachments = [
                      {
                        name:
                          message.attachment_name
                      }
                    ];
                  }
                }

                return {
                  ...message,
                  attachments
                };
              });

          return json({
            messages
          });

        } catch (error) {

          console.error(
            "ERROR GET /api/messages:",
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


      /* ---------- ELIMINAR MENSAJE ---------- */

      if (request.method === "DELETE") {

        if (!isAdmin(request)) {
          return json(
            {
              message:
                "No autorizado."
            },
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


          /*
           * Buscamos primero los archivos
           * para poder eliminarlos del KV.
           */
          const row =
            await env.DB
              .prepare(`
                SELECT attachment_name
                FROM messages
                WHERE id = ?
              `)
              .bind(id)
              .first();


          if (
            row &&
            row.attachment_name &&
            env.MESSAGE_FILES
          ) {

            try {

              const attachments =
                JSON.parse(
                  row.attachment_name
                );

              if (
                Array.isArray(
                  attachments
                )
              ) {

                for (
                  const file
                  of attachments
                ) {

                  if (
                    file &&
                    file.key
                  ) {
                    await env.MESSAGE_FILES.delete(
                      file.key
                    );
                  }
                }
              }

            } catch (error) {
              console.error(
                "No se pudieron limpiar los archivos:",
                error
              );
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
            "ERROR DELETE /api/messages:",
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


    /* =========================================================
       ARCHIVOS DE MENSAJES
    ========================================================= */

    if (
      url.pathname ===
      "/api/message-file"
    ) {

      if (!isAdmin(request)) {
        return new Response(
          "No autorizado.",
          {
            status: 401
          }
        );
      }

      if (!env.MESSAGE_FILES) {
        return new Response(
          "Almacenamiento no configurado.",
          {
            status: 500
          }
        );
      }

      try {

        const messageId =
          Number(
            url.searchParams.get(
              "message"
            )
          );

        const index =
          Number(
            url.searchParams.get(
              "file"
            )
          );

        if (
          !Number.isInteger(
            messageId
          ) ||
          messageId <= 0
        ) {
          return new Response(
            "Mensaje inválido.",
            {
              status: 400
            }
          );
        }

        if (
          !Number.isInteger(index) ||
          index < 0
        ) {
          return new Response(
            "Archivo inválido.",
            {
              status: 400
            }
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

        if (
          !row ||
          !row.attachment_name
        ) {
          return new Response(
            "Archivo no encontrado.",
            {
              status: 404
            }
          );
        }

        let attachments = [];

        try {
          attachments =
            JSON.parse(
              row.attachment_name
            );
        } catch (error) {
          attachments = [];
        }

        if (
          !Array.isArray(
            attachments
          ) ||
          !attachments[index]
        ) {
          return new Response(
            "Archivo no encontrado.",
            {
              status: 404
            }
          );
        }

        const file =
          attachments[index];

        if (!file.key) {
          return new Response(
            "Archivo no encontrado.",
            {
              status: 404
            }
          );
        }

        const object =
          await env.MESSAGE_FILES.get(
            file.key
          );

        if (!object) {
          return new Response(
            "Archivo no encontrado.",
            {
              status: 404
            }
          );
        }

        const headers =
          new Headers();

        object.writeHttpMetadata(
          headers
        );

        headers.set(
          "content-disposition",
          'attachment; filename="' +
            sanitizeFileName(
              file.name ||
              "archivo"
            ) +
            '"'
        );

        headers.set(
          "cache-control",
          "no-store"
        );

        return new Response(
          object.body,
          {
            headers
          }
        );

      } catch (error) {

        console.error(
          "ERROR /api/message-file:",
          error
        );

        return new Response(
          "No se pudo descargar el archivo.",
          {
            status: 500
          }
        );
      }
    }


    /* =========================================================
       SITIO ESTÁTICO
    ========================================================= */

    if (env.ASSETS) {
      return env.ASSETS.fetch(
        request
      );
    }

    return new Response(
      "I.N STYLE",
      {
        status: 200,
        headers: {
          "content-type":
            "text/plain; charset=UTF-8"
        }
      }
    );
  },


  /* =========================================================
     CRON
  ========================================================= */

  async scheduled(event, env, ctx) {

    ctx.waitUntil(
      cleanupMessages(
        env.DB
      )
    );
  }
};


/* =========================================================
   RESPUESTAS
========================================================= */

function json(
  data,
  status = 200
) {

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "content-type":
          "application/json; charset=UTF-8",
        "cache-control":
          "no-store"
      }
    }
  );
}


/* =========================================================
   ADMIN
========================================================= */

function isAdmin(request) {

  /*
   * Sesión segura por cookie.
   */
  const cookie =
    request.headers.get(
      "Cookie"
    ) || "";

  if (
    cookie.includes(
      "instyle_admin_session=1"
    )
  ) {
    return true;
  }


  /*
   * Compatibilidad con el sistema
   * actual del sitio.
   */
  if (
    request.headers.get(
      "X-INSTYLE-ADMIN"
    ) ===
    "INSTYLE2026"
  ) {
    return true;
  }

  return false;
}


/* =========================================================
   LIMPIEZA DE TEXTO
========================================================= */

function clean(value) {

  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  return String(
    value
  ).trim();
}


/* =========================================================
   EMAIL
========================================================= */

function isValidEmail(
  email
) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}


/* =========================================================
   ESTADO D1
========================================================= */

async function saveStateKey(
  db,
  key,
  value
) {

  const stateValue =
    value === null ||
    value === undefined
      ? null
      : String(value);

  if (
    stateValue === null
  ) {

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
        state_value =
          excluded.state_value,
        updated_at =
          excluded.updated_at
    `)
    .bind(
      key,
      stateValue,
      new Date().toISOString()
    )
    .run();
}


/* =========================================================
   NOMBRE DE ARCHIVO
========================================================= */

function sanitizeFileName(
  name
) {

  return String(
    name || "archivo"
  )
    .normalize("NFKD")
    .replace(
      /[\u0300-\u036f]/g,
      ""
    )
    .replace(
      /[^a-zA-Z0-9._-]/g,
      "_"
    )
    .slice(
      0,
      180
    );
}


/* =========================================================
   PARTE DE RUTA
========================================================= */

function sanitizePathPart(
  value
) {

  return String(
    value || "site"
  )
    .replace(
      /[^a-zA-Z0-9_-]/g,
      "_"
    )
    .slice(
      0,
      60
    );
}


/* =========================================================
   LIMPIEZA SEMANAL DE MENSAJES
========================================================= */

async function cleanupMessages(
  db
) {

  /*
   * Conservamos los mensajes recientes.
   * Más adelante podemos dejar esto
   * exactamente para domingo mediante cron.
   */

  const cutoff =
    new Date(
      Date.now() -
        7 *
          24 *
          60 *
          60 *
          1000
    ).toISOString();

  await db
    .prepare(
      "DELETE FROM messages WHERE created_at < ?"
    )
    .bind(cutoff)
    .run();
}
