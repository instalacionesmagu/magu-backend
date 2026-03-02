const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3001;

// ── Supabase client ──────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY  // service role key (backend only)
);

// ── Middleware ───────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json({ limit: '50mb' }));

// Multer — memory storage (we upload directly to Supabase Storage)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

// ── Auth helpers ─────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'magu-secret-change-in-production';

function signToken(user) {
  return jwt.sign({ id: user.id, rol: user.rol, nombre: user.nombre }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function adminOnly(req, res, next) {
  if (req.user?.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

// ============================================================
// AUTH
// ============================================================

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

  const { data: user, error } = await supabase
    .from('usuarios')
    .select('*')
    .eq('email', email.toLowerCase())
    .eq('activo', true)
    .single();

  if (error || !user) return res.status(401).json({ error: 'Credenciales incorrectas' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });

  // Update last login
  await supabase.from('usuarios').update({ ultimo_acceso: new Date().toISOString() }).eq('id', user.id);

  const { password_hash, ...safeUser } = user;
  res.json({ token: signToken(user), user: safeUser });
});

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const { data: user } = await supabase
    .from('usuarios').select('id,nombre,email,rol,telefono,avatar_url,activo,ultimo_acceso').eq('id', req.user.id).single();
  res.json(user);
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { data: user } = await supabase.from('usuarios').select('*').eq('id', req.user.id).single();
  const ok = await bcrypt.compare(currentPassword, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Contraseña actual incorrecta' });
  const hash = await bcrypt.hash(newPassword, 12);
  await supabase.from('usuarios').update({ password_hash: hash }).eq('id', req.user.id);
  res.json({ success: true });
});

// ============================================================
// USUARIOS (Admin)
// ============================================================

// GET /api/usuarios
app.get('/api/usuarios', authMiddleware, adminOnly, async (req, res) => {
  const { data, error } = await supabase
    .from('usuarios').select('id,nombre,email,rol,telefono,activo,ultimo_acceso,creado_en').order('nombre');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// POST /api/usuarios
app.post('/api/usuarios', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, email, password, rol = 'operario', telefono } = req.body;
  if (!nombre || !email || !password) return res.status(400).json({ error: 'Nombre, email y contraseña requeridos' });

  const hash = await bcrypt.hash(password, 12);
  const { data, error } = await supabase.from('usuarios').insert({
    nombre, email: email.toLowerCase(), password_hash: hash,
    rol, telefono, activo: true
  }).select('id,nombre,email,rol,telefono,activo').single();

  if (error) return res.status(400).json({ error: error.message.includes('unique') ? 'Email ya registrado' : error.message });
  res.status(201).json(data);
});

// PUT /api/usuarios/:id
app.put('/api/usuarios/:id', authMiddleware, adminOnly, async (req, res) => {
  const { nombre, email, rol, telefono, activo, password } = req.body;
  const updates = { nombre, rol, telefono, activo };
  if (email) updates.email = email.toLowerCase();
  if (password) updates.password_hash = await bcrypt.hash(password, 12);

  const { data, error } = await supabase.from('usuarios').update(updates)
    .eq('id', req.params.id).select('id,nombre,email,rol,telefono,activo').single();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// DELETE /api/usuarios/:id
app.delete('/api/usuarios/:id', authMiddleware, adminOnly, async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  await supabase.from('usuarios').update({ activo: false }).eq('id', req.params.id);
  res.json({ success: true });
});

// ============================================================
// CONFIGURACIÓN (Admin)
// ============================================================

// GET /api/config
app.get('/api/config', authMiddleware, async (req, res) => {
  const { data } = await supabase.from('configuracion').select('*').single();
  res.json(data || {});
});

// PUT /api/config
app.put('/api/config', authMiddleware, adminOnly, async (req, res) => {
  const { data: existing } = await supabase.from('configuracion').select('id').single();
  let result;
  if (existing) {
    const { data } = await supabase.from('configuracion').update(req.body).eq('id', existing.id).select().single();
    result = data;
  } else {
    const { data } = await supabase.from('configuracion').insert(req.body).select().single();
    result = data;
  }
  res.json(result);
});

// ============================================================
// PARTES DE TRABAJO
// ============================================================

// GET /api/partes  — admin ve todos, operario solo los suyos
app.get('/api/partes', authMiddleware, async (req, res) => {
  let query = supabase.from('partes').select(`
    *, 
    asignado:usuarios!partes_asignado_a_fkey(id, nombre, email),
    fotos(id, url, tipo, descripcion, creado_en)
  `).order('creado_en', { ascending: false });

  if (req.user.rol !== 'admin') {
    query = query.eq('asignado_a', req.user.id);
  }

  // Filters
  if (req.query.estado) query = query.eq('estado', req.query.estado);
  if (req.query.tipo_trabajo) query = query.eq('tipo_trabajo', req.query.tipo_trabajo);
  if (req.query.urgencia) query = query.eq('urgencia', req.query.urgencia);

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// GET /api/partes/:id
app.get('/api/partes/:id', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('partes').select(`
    *,
    asignado:usuarios!partes_asignado_a_fkey(id, nombre, email, telefono),
    fotos(id, url, tipo, descripcion, creado_en)
  `).eq('id', req.params.id).single();

  if (error || !data) return res.status(404).json({ error: 'Parte no encontrado' });

  // Operario can only see their own
  if (req.user.rol !== 'admin' && data.asignado_a !== req.user.id) {
    return res.status(403).json({ error: 'Sin acceso a este parte' });
  }
  res.json(data);
});

// POST /api/partes
app.post('/api/partes', authMiddleware, adminOnly, async (req, res) => {
  // Get next number
  const { count } = await supabase.from('partes').select('*', { count: 'exact', head: true });
  const numero = `PT-${new Date().getFullYear()}-${String((count || 0) + 1).padStart(4, '0')}`;

  const { data, error } = await supabase.from('partes').insert({
    ...req.body,
    numero,
    creado_por: req.user.id
  }).select('*, asignado:usuarios!partes_asignado_a_fkey(id,nombre,email)').single();

  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json(data);
});

// PUT /api/partes/:id
app.put('/api/partes/:id', authMiddleware, async (req, res) => {
  const { data: parte } = await supabase.from('partes').select('asignado_a').eq('id', req.params.id).single();
  if (!parte) return res.status(404).json({ error: 'Parte no encontrado' });

  // Operarios can only update estado, horas_reales, observaciones
  let updates = req.body;
  if (req.user.rol !== 'admin') {
    if (parte.asignado_a !== req.user.id) return res.status(403).json({ error: 'Sin acceso' });
    const { estado, horas_reales, observaciones } = req.body;
    updates = { estado, horas_reales, observaciones };
  }

  const { data, error } = await supabase.from('partes').update({
    ...updates, actualizado_en: new Date().toISOString()
  }).eq('id', req.params.id).select('*, asignado:usuarios!partes_asignado_a_fkey(id,nombre,email), fotos(*)').single();

  if (error) return res.status(400).json({ error: error.message });
  res.json(data);
});

// DELETE /api/partes/:id
app.delete('/api/partes/:id', authMiddleware, adminOnly, async (req, res) => {
  // Delete fotos from storage first
  const { data: fotos } = await supabase.from('fotos').select('storage_path').eq('parte_id', req.params.id);
  if (fotos?.length) {
    const paths = fotos.map(f => f.storage_path).filter(Boolean);
    if (paths.length) await supabase.storage.from('fotos').remove(paths);
  }
  await supabase.from('fotos').delete().eq('parte_id', req.params.id);
  await supabase.from('partes').delete().eq('id', req.params.id);
  res.json({ success: true });
});

// ============================================================
// FOTOS
// ============================================================

// POST /api/partes/:id/fotos — multipart upload
app.post('/api/partes/:id/fotos', authMiddleware, upload.array('fotos', 20), async (req, res) => {
  const parteId = req.params.id;

  // Check access
  const { data: parte } = await supabase.from('partes').select('asignado_a').eq('id', parteId).single();
  if (!parte) return res.status(404).json({ error: 'Parte no encontrado' });
  if (req.user.rol !== 'admin' && parte.asignado_a !== req.user.id) {
    return res.status(403).json({ error: 'Sin acceso' });
  }

  const results = [];
  for (const file of req.files) {
    const ext = file.originalname.split('.').pop().toLowerCase();
    const storagePath = `${parteId}/${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;

    // Upload to Supabase Storage
    const { error: uploadError } = await supabase.storage
      .from('fotos')
      .upload(storagePath, file.buffer, { contentType: file.mimetype, upsert: false });

    if (uploadError) { console.error(uploadError); continue; }

    // Get public URL
    const { data: { publicUrl } } = supabase.storage.from('fotos').getPublicUrl(storagePath);

    // Save to DB
    const { data: fotoRecord } = await supabase.from('fotos').insert({
      parte_id: parteId,
      url: publicUrl,
      storage_path: storagePath,
      tipo: req.body.tipo || 'general',
      descripcion: req.body.descripcion || '',
      nombre_original: file.originalname,
      tamano: file.size,
      subido_por: req.user.id
    }).select().single();

    results.push(fotoRecord);
  }

  res.json({ fotos: results, total: results.length });
});

// DELETE /api/partes/:id/fotos/:fotoId
app.delete('/api/partes/:id/fotos/:fotoId', authMiddleware, async (req, res) => {
  const { data: foto } = await supabase.from('fotos').select('*').eq('id', req.params.fotoId).eq('parte_id', req.params.id).single();
  if (!foto) return res.status(404).json({ error: 'Foto no encontrada' });

  // Check access
  const { data: parte } = await supabase.from('partes').select('asignado_a').eq('id', req.params.id).single();
  if (req.user.rol !== 'admin' && parte?.asignado_a !== req.user.id) {
    return res.status(403).json({ error: 'Sin acceso' });
  }

  if (foto.storage_path) await supabase.storage.from('fotos').remove([foto.storage_path]);
  await supabase.from('fotos').delete().eq('id', req.params.fotoId);
  res.json({ success: true });
});

// ============================================================
// AI ESTIMACIÓN
// ============================================================
app.post('/api/ai/estimar-tiempo', authMiddleware, async (req, res) => {
  const { descripcion, tipo_trabajo, urgencia, fotos_info } = req.body;
  if (!descripcion) return res.status(400).json({ error: 'Se requiere descripción' });

  // Get tarifa from config
  const { data: config } = await supabase.from('configuracion').select('tarifa_hora').single();
  const tarifa = config?.tarifa_hora || 45;

  try {
    const fotoCtx = fotos_info?.length ? `\nFotos disponibles: ${fotos_info.length} foto(s) — tipos: ${fotos_info.map(f=>f.tipo).join(', ')}.` : '';
    const prompt = `Eres un experto en instalaciones eléctricas, telecomunicaciones y HVAC (climatización) en España, Formentera (Baleares).

Analiza el siguiente trabajo y proporciona estimación:

Tipo: ${tipo_trabajo || 'general'}
Urgencia: ${urgencia || 'normal'}
Descripción: ${descripcion}${fotoCtx}

Responde SOLO JSON:
{
  "tiempo_estimado_horas": <decimal>,
  "tiempo_minimo_horas": <decimal>,
  "tiempo_maximo_horas": <decimal>,
  "confianza": <"alta"|"media"|"baja">,
  "desglose": [{"fase": "nombre", "horas": <n>, "descripcion": "desc"}],
  "materiales_estimados": ["item1"],
  "complejidad": <"baja"|"media"|"alta"|"muy_alta">,
  "notas": "texto",
  "precio_estimado_mano_obra": <euros, tarifa ${tarifa}€/h>,
  "factores_riesgo": ["factor1"]
}`;

    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 1024, messages: [{ role: 'user', content: prompt }] })
    });
    const data = await response.json();
    const text = data.content[0].text;
    const match = text.match(/\{[\s\S]*\}/);
    const estimacion = JSON.parse(match[0]);
    res.json({ success: true, estimacion });
  } catch(e) {
    const base = tipo_trabajo?.includes('hvac') ? 4 : tipo_trabajo?.includes('tel') ? 2 : 3;
    res.json({ success: true, fallback: true, estimacion: {
      tiempo_estimado_horas: base, tiempo_minimo_horas: base * 0.7, tiempo_maximo_horas: base * 1.5,
      confianza: 'baja', desglose: [{ fase: 'Trabajo general', horas: base, descripcion: 'Estimación automática' }],
      materiales_estimados: [], complejidad: 'media',
      notas: 'Estimación automática. Configure ANTHROPIC_API_KEY para estimaciones precisas.',
      precio_estimado_mano_obra: base * tarifa, factores_riesgo: []
    }});
  }
});

// ============================================================
// GOOGLE CALENDAR
// ============================================================
app.get('/api/google/auth-url', authMiddleware, (req, res) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) return res.json({ url: null, configured: false });
  const redirectUri = process.env.GOOGLE_REDIRECT_URI;
  const scope = encodeURIComponent('https://www.googleapis.com/auth/calendar');
  const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}&access_type=offline&prompt=consent`;
  res.json({ url, configured: true });
});

app.get('/api/google/calendars', authMiddleware, async (req, res) => {
  const { accessToken } = req.query;
  if (!accessToken) return res.status(400).json({ error: 'Token requerido' });
  const response = await fetch('https://www.googleapis.com/calendar/v3/users/me/calendarList', { headers: { Authorization: `Bearer ${accessToken}` } });
  res.json(await response.json());
});

app.post('/api/partes/:id/calendar', authMiddleware, async (req, res) => {
  const { accessToken, startDateTime, endDateTime, calendarId } = req.body;
  const { data: p } = await supabase.from('partes').select('*, asignado:usuarios!partes_asignado_a_fkey(nombre)').eq('id', req.params.id).single();
  if (!p) return res.status(404).json({ error: 'Parte no encontrado' });
  if (!accessToken) return res.status(400).json({ error: 'Token requerido' });

  const event = {
    summary: `[${p.numero}] ${p.titulo || 'Parte de trabajo'}`,
    description: `Cliente: ${p.cliente||'N/A'}\nDirección: ${p.direccion||'N/A'}\nTipo: ${p.tipo_trabajo||'N/A'}\nDescripción: ${p.descripcion||'N/A'}\nTécnico: ${p.asignado?.nombre||'N/A'}`,
    location: p.direccion || '',
    start: { dateTime: startDateTime, timeZone: 'Europe/Madrid' },
    end: { dateTime: endDateTime || new Date(new Date(startDateTime).getTime() + 2 * 3600000).toISOString(), timeZone: 'Europe/Madrid' },
    colorId: p.urgencia === 'urgente' ? '11' : '2',
    reminders: { useDefault: false, overrides: [{ method: 'email', minutes: 60 }, { method: 'popup', minutes: 30 }] }
  };

  const r = await fetch(`https://www.googleapis.com/calendar/v3/calendars/${calendarId||'primary'}/events`, {
    method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify(event)
  });
  if (!r.ok) return res.status(400).json({ error: 'Error Google Calendar', details: await r.json() });
  const calEvent = await r.json();
  await supabase.from('partes').update({ google_event_id: calEvent.id, google_event_link: calEvent.htmlLink, fecha_programada: startDateTime }).eq('id', req.params.id);
  res.json({ success: true, event: calEvent, link: calEvent.htmlLink });
});

// ============================================================
// STATS
// ============================================================
app.get('/api/stats', authMiddleware, async (req, res) => {
  let query = supabase.from('partes').select('estado, urgencia, creado_en', { count: 'exact' });
  if (req.user.rol !== 'admin') query = query.eq('asignado_a', req.user.id);
  const { data: partes, count } = await query;

  const { count: fotosCount } = await supabase.from('fotos').select('*', { count: 'exact', head: true });
  const now = new Date();
  const thisMes = partes?.filter(p => {
    const d = new Date(p.creado_en);
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  }).length || 0;

  res.json({
    total: count || 0,
    pendientes: partes?.filter(p => p.estado === 'pendiente').length || 0,
    en_progreso: partes?.filter(p => p.estado === 'en_progreso').length || 0,
    completados: partes?.filter(p => p.estado === 'completado').length || 0,
    urgentes: partes?.filter(p => p.urgencia === 'urgente' && p.estado !== 'completado').length || 0,
    este_mes: thisMes,
    fotos_total: req.user.rol === 'admin' ? (fotosCount || 0) : 0
  });
});

// ── Health ──────────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString(), version: '2.0.0' }));

app.listen(PORT, () => console.log(`⚡ MaGu Backend v2 en puerto ${PORT}`));
