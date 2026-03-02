-- ============================================================
-- MaGu Multiservicios — Setup SQL para Supabase
-- Ejecutar en: Supabase → SQL Editor → New query → Run
-- ============================================================

-- ── USUARIOS ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS usuarios (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  nombre TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  rol TEXT NOT NULL DEFAULT 'operario' CHECK (rol IN ('admin', 'operario')),
  telefono TEXT,
  avatar_url TEXT,
  activo BOOLEAN DEFAULT true,
  ultimo_acceso TIMESTAMPTZ,
  creado_en TIMESTAMPTZ DEFAULT NOW()
);

-- ── CONFIGURACIÓN ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS configuracion (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  nombre_empresa TEXT DEFAULT 'MaGu Multiservicios S.L.',
  logo_url TEXT,
  telefono_empresa TEXT DEFAULT '+34 971 000 000',
  email_empresa TEXT DEFAULT 'info@magumulti.com',
  direccion_empresa TEXT DEFAULT 'Formentera, Baleares',
  tarifa_hora NUMERIC DEFAULT 45,
  tipos_trabajo JSONB DEFAULT '["electrico","telecomunicaciones","hvac","mantenimiento","averia","otro"]',
  estados_parte JSONB DEFAULT '["pendiente","en_progreso","completado","cancelado"]',
  color_primario TEXT DEFAULT '#3d7eff',
  actualizado_en TIMESTAMPTZ DEFAULT NOW()
);

-- ── PARTES DE TRABAJO ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS partes (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  numero TEXT UNIQUE NOT NULL,
  titulo TEXT,
  cliente TEXT NOT NULL,
  telefono TEXT,
  email_cliente TEXT,
  direccion TEXT,
  tipo_trabajo TEXT DEFAULT 'electrico',
  urgencia TEXT DEFAULT 'normal' CHECK (urgencia IN ('urgente','normal','baja')),
  estado TEXT DEFAULT 'pendiente' CHECK (estado IN ('pendiente','en_progreso','completado','cancelado')),
  descripcion TEXT,
  materiales TEXT,
  observaciones TEXT,
  horas_estimadas NUMERIC,
  horas_reales NUMERIC,
  asignado_a UUID REFERENCES usuarios(id),
  creado_por UUID REFERENCES usuarios(id),
  google_event_id TEXT,
  google_event_link TEXT,
  fecha_programada TIMESTAMPTZ,
  creado_en TIMESTAMPTZ DEFAULT NOW(),
  actualizado_en TIMESTAMPTZ DEFAULT NOW()
);

-- ── FOTOS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS fotos (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  parte_id UUID NOT NULL REFERENCES partes(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  storage_path TEXT,
  tipo TEXT DEFAULT 'general' CHECK (tipo IN ('antes','durante','despues','problema','material','general')),
  descripcion TEXT,
  nombre_original TEXT,
  tamano INTEGER,
  subido_por UUID REFERENCES usuarios(id),
  creado_en TIMESTAMPTZ DEFAULT NOW()
);

-- ── ÍNDICES ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_partes_asignado ON partes(asignado_a);
CREATE INDEX IF NOT EXISTS idx_partes_estado ON partes(estado);
CREATE INDEX IF NOT EXISTS idx_fotos_parte ON fotos(parte_id);

-- ── ROW LEVEL SECURITY ────────────────────────────────────────
-- (Opcional para Supabase — el backend usa service key que bypasea RLS)
ALTER TABLE usuarios ENABLE ROW LEVEL SECURITY;
ALTER TABLE partes ENABLE ROW LEVEL SECURITY;
ALTER TABLE fotos ENABLE ROW LEVEL SECURITY;
ALTER TABLE configuracion ENABLE ROW LEVEL SECURITY;

-- Permitir todo desde service_role (backend)
CREATE POLICY "service_role_all" ON usuarios FOR ALL TO service_role USING (true);
CREATE POLICY "service_role_all" ON partes FOR ALL TO service_role USING (true);
CREATE POLICY "service_role_all" ON fotos FOR ALL TO service_role USING (true);
CREATE POLICY "service_role_all" ON configuracion FOR ALL TO service_role USING (true);

-- ── STORAGE BUCKET ────────────────────────────────────────────
-- Ejecuta esto también para crear el bucket de fotos:
INSERT INTO storage.buckets (id, name, public)
VALUES ('fotos', 'fotos', true)
ON CONFLICT (id) DO NOTHING;

-- Política storage: service_role puede todo
CREATE POLICY "service_role_storage" ON storage.objects FOR ALL TO service_role USING (true);
-- Acceso público a leer fotos (URLs públicas)
CREATE POLICY "public_read_fotos" ON storage.objects FOR SELECT TO public USING (bucket_id = 'fotos');

-- ── USUARIO ADMIN POR DEFECTO ─────────────────────────────────
-- Contraseña: Admin2024! (cámbiala después de entrar)
-- Hash generado con bcrypt salt 12
INSERT INTO usuarios (nombre, email, password_hash, rol)
VALUES (
  'Samuel (Admin)',
  'admin@magu.es',
  '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TqonQQp0X.BnT7hGy/5zQDkFJRVe',
  'admin'
) ON CONFLICT (email) DO NOTHING;

-- ── CONFIGURACIÓN INICIAL ─────────────────────────────────────
INSERT INTO configuracion (nombre_empresa, tarifa_hora)
VALUES ('MaGu Multiservicios S.L.', 45)
ON CONFLICT DO NOTHING;

-- ── VERIFICACIÓN ──────────────────────────────────────────────
SELECT 'Setup completado ✅' as resultado;
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
