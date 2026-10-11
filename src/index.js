export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // =========================
    // API — INICIAR SESIÓN ADMIN
    // =========================

    if (url.pathname === "/api/admin-login") {
      if (request.method !== "POST") {
        return json({ message: "Método no permitido." }, 405);
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
          return json({ message: "Clave incorrecta." }, 401);
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
    // API — ARCHIVOS DE MENSAJES
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

        const messageId = Number(
          url.searchParams.get("message")
        );

        const fileIndex = Number(
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


        const row = await env.DB
          .prepare(`
            SELECT
              attachment_name,
              attachment_type,
              attachment_size
            FROM messages
            WHERE id = ?
          `)
          .bind(messageId)
          .first();


        if (!row) {
          return json(
            { message: "Mensaje no encontrado." },
            404
          );
        }


        const files = parseAttachmentMetadata(
          row.attachment_name,
          row.attachment_type,
          row.attachment_size
        );


        const file = files[fileIndex];


        if (!file || !file.key) {
          return json(
            { message: "Archivo no encontrado." },
            404
          );
        }


        const storedFile =
          await env.MESSAGE_FILES.get(
            file.key,
            { type: "arrayBuffer" }
          );


        if (!storedFile) {
          return json(
            { message: "El archivo ya no está disponible." },
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
              "content-type":
                file.type ||
                "application/octet-stream",

              "content-length":
                String(file.size || storedFile.byteLength),

              "content-disposition":
                `attachment; filename="${safeName}"`,

              "cache-control":
                "private, no-store"
            }
          }
        );


      } catch (error) {

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
    // API — MENSAJES
    // =========================

    if (url.pathname === "/api/messages") {


      // =========================
      // RECIBIR MENSAJES
      // =========================

      if (request.method === "POST") {

        try {

          const form =
            await request.formData();


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


          // =========================
          // VALIDACIONES
          // =========================

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


          // =========================
          // ARCHIVOS
          // =========================

          const attachments =
            form.getAll("attachment");


          const validFiles = [];


          let totalSize = 0;


          const MAX_TOTAL_SIZE =
            8 * 1024 * 1024;


          for (const attachment of attachments) {

            if (
              !attachment ||
              typeof attachment !== "object" ||
              !("name" in attachment) ||
              !attachment.name
            ) {
              continue;
            }


            const fileName =
              String(
                attachment.name || ""
              );


            const fileType =
              String(
                attachment.type || ""
              );


            const fileSize =
              Number(
                attachment.size || 0
              );


            if (fileSize <= 0) {
              continue;
            }


            totalSize += fileSize;


            if (totalSize > MAX_TOTAL_SIZE) {
              return json(
                {
                  message:
                    "El tamaño total de los archivos no puede superar los 8 MB."
                },
                400
              );
            }


            validFiles.push({
              originalFile: attachment,
              name: fileName,
              type: fileType,
              size: fileSize
            });
          }


          // =========================
          // GUARDAR MENSAJE EN D1
          // =========================

          const createdAt =
            new Date().toISOString();


          const insertResult =
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
                "[]",
                "[]",
                "[]",
                createdAt
              )
              .run();


          const messageId =
            Number(
              insertResult.meta?.last_row_id
            );


          if (
            !Number.isInteger(messageId) ||
            messageId <= 0
          ) {
            throw new Error(
              "No se pudo obtener el ID del mensaje."
            );
          }


          // =========================
          // GUARDAR ARCHIVOS EN KV
          // =========================

          const fileMetadata = [];


          try {

            for (
              let index = 0;
              index < validFiles.length;
              index++
            ) {

              const file =
                validFiles[index];


              const key =
                `message-${messageId}-file-${index}-${crypto.randomUUID()}`;


              const fileBuffer =
                await file.originalFile.arrayBuffer();


              await env.MESSAGE_FILES.put(
                key,
                fileBuffer,
                {
                  expirationTtl:
                    60 * 60 * 24 * 30
                }
              );


              fileMetadata.push({
                key,
                name: file.name,
                type: file.type,
                size: file.size
              });
            }


          } catch (fileError) {

            // Si falla un archivo, eliminar
            // los que ya hayan sido guardados.
            for (const savedFile of fileMetadata) {
              try {
                await env.MESSAGE_FILES.delete(
                  savedFile.key
                );
              } catch (error) {}
            }


            await env.DB
              .prepare(
                "DELETE FROM messages WHERE id = ?"
              )
              .bind(messageId)
              .run();


            throw fileError;
          }


          // =========================
          // GUARDAR METADATA DE ARCHIVOS
          // =========================

          const names =
            fileMetadata.map(
              file => file.name
            );


          const types =
            fileMetadata.map(
              file => file.type
            );


          const sizes =
            fileMetadata.map(
              file => file.size
            );


          await env.DB
            .prepare(`
              UPDATE messages
              SET
                attachment_name = ?,
                attachment_type = ?,
                attachment_size = ?
              WHERE id = ?
            `)
            .bind(
              JSON.stringify(names),
              JSON.stringify(types),
              JSON.stringify(sizes),
              messageId
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
      // SOLO ADMIN
      // =========================

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
              row => ({
                ...row,
                attachments:
                  parseAttachmentMetadata(
                    row.attachment_name,
                    row.attachment_type,
                    row.attachment_size
                  )
              })
            );


          return json({
            messages
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
      // ELIMINAR MENSAJE
      // SOLO ADMIN
      // =========================

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


          // Buscar archivos antes de eliminar
          // el mensaje.
          const row =
            await env.DB
              .prepare(`
                SELECT
                  attachment_name,
                  attachment_type,
                  attachment_size
                FROM messages
                WHERE id = ?
              `)
              .bind(id)
              .first();


          if (row) {

            const files =
              parseAttachmentMetadata(
                row.attachment_name,
                row.attachment_type,
                row.attachment_size
              );


            // Eliminar archivos de KV
            for (const file of files) {

              if (file.key) {

                try {
                  await env.MESSAGE_FILES.delete(
                    file.key
                  );
                } catch (error) {}
              }
            }
          }


          // Eliminar mensaje
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


  // =========================
  // LIMPIEZA PROGRAMADA
  // =========================

  async scheduled(event, env, ctx) {

    ctx.waitUntil(
      cleanupWeeklyMessages(env)
    );

  }
};


// ========================================
// FUNCIONES AUXILIARES
// ========================================


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


// ========================================
// VERIFICAR SESIÓN ADMIN
// ========================================

function isAdmin(
  request,
  env
) {

  const cookieHeader =
    request.headers.get("Cookie") || "";


  const sessionCookie =
    cookieHeader
      .split(";")
      .map(
        item => item.trim()
      )
      .find(
        item =>
          item.startsWith(
            "instyle_admin_session="
          )
      );


  if (
    !env.INSTYLE_ADMIN_SECRET ||
    !sessionCookie
  ) {
    return false;
  }


  try {

    const sessionValue =
      decodeURIComponent(
        sessionCookie.slice(
          "instyle_admin_session="
            .length
        )
      );


    return (
      sessionValue ===
      env.INSTYLE_ADMIN_SECRET
    );


  } catch (error) {

    return false;
  }
}


// ========================================
// LIMPIAR TEXTO
// ========================================

function clean(value) {

  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  return String(value).trim();
}


// ========================================
// VALIDAR CORREO
// ========================================

function isValidEmail(email) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}


// ========================================
// LEER METADATA DE ARCHIVOS
// ========================================

function parseAttachmentMetadata(
  names,
  types,
  sizes
) {

  try {

    const parsedNames =
      JSON.parse(
        names || "[]"
      );


    const parsedTypes =
      JSON.parse(
        types || "[]"
      );


    const parsedSizes =
      JSON.parse(
        sizes || "[]"
      );


    if (
      !Array.isArray(parsedNames) ||
      !Array.isArray(parsedTypes) ||
      !Array.isArray(parsedSizes)
    ) {
      return [];
    }


    return parsedNames.map(
      (name, index) => {

        return {
          key: extractStoredKey(name),
          name: getCleanFileName(name),
          type:
            parsedTypes[index] || "",
          size:
            Number(
              parsedSizes[index] || 0
            )
        };

      }
    );


  } catch (error) {

    return [];
  }
}


// ========================================
// EXTRAER INFORMACIÓN DEL ARCHIVO
// ========================================

function extractStoredKey(
  value
) {

  const text =
    String(value || "");


  if (
    text.includes("::KEY::")
  ) {
    return text.split(
      "::KEY::"
    )[1] || "";
  }


  return "";
}


// ========================================
// NOMBRE VISIBLE DEL ARCHIVO
// ========================================

function getCleanFileName(
  value
) {

  const text =
    String(value || "");


  if (
    text.includes("::KEY::")
  ) {
    return text.split(
      "::KEY::"
    )[0];
  }


  return text;
}


// ========================================
// NOMBRE SEGURO PARA DESCARGA
// ========================================

function sanitizeFileName(
  value
) {

  return String(value || "archivo")
    .replace(
      /[\\\/:*?"<>|]/g,
      "_"
    )
    .replace(
      /[\r\n]/g,
      "_"
    )
    .slice(
      0,
      180
    );
}


// ========================================
// GUARDAR ESTADO DEL SITIO
// ========================================

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


// ========================================
// LIMPIEZA SEMANAL
// ========================================

async function cleanupWeeklyMessages(
  env
) {

  const rows =
    await env.DB
      .prepare(`
        SELECT
          id,
          attachment_name,
          attachment_type,
          attachment_size
        FROM messages
      `)
      .all();


  for (
    const row of
      rows.results || []
  ) {

    const files =
      parseAttachmentMetadata(
        row.attachment_name,
        row.attachment_type,
        row.attachment_size
      );


    // Eliminar archivos
    for (const file of files) {

      if (file.key) {

        try {

          await env.MESSAGE_FILES.delete(
            file.key
          );

        } catch (error) {}
      }
    }


    // Eliminar mensaje
    await env.DB
      .prepare(
        "DELETE FROM messages WHERE id = ?"
      )
      .bind(row.id)
      .run();
  }
}
