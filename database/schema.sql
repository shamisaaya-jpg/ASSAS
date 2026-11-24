-- =====================================================================
-- ASSAS - Analyse, Surveillance et Supervision des Accès Suspects
-- Schéma de la base PostgreSQL
--
-- Modèle :  users (1) ──< analyses (1) ──< alerts
--   - un administrateur réalise plusieurs analyses
--   - une analyse produit plusieurs alertes
--
-- Exécution (conteneur Docker du projet) :
--   docker exec -i assas-postgres psql -U assas -d assas < database/schema.sql
-- Le script peut être relancé sans risque (IF NOT EXISTS).
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Administrateurs autorisés à se connecter à ASSAS
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                 -- mot de passe haché (Werkzeug), jamais en clair
    created_at    TIMESTAMP DEFAULT NOW()
);

-- ---------------------------------------------------------------------
-- 2. Une ligne par fichier de logs analysé
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analyses (
    id          SERIAL PRIMARY KEY,
    filename    TEXT,                            -- nom du fichier importé
    analyzed_by INTEGER REFERENCES users(id),    -- administrateur qui a lancé l'analyse
    total       INTEGER DEFAULT 0,               -- nombre total d'alertes
    critical    INTEGER DEFAULT 0,
    high        INTEGER DEFAULT 0,
    medium      INTEGER DEFAULT 0,
    low         INTEGER DEFAULT 0,
    created_at  TIMESTAMP DEFAULT NOW()          -- date de l'analyse
);

-- ---------------------------------------------------------------------
-- 3. Alertes produites par les règles de détection
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL PRIMARY KEY,
    analysis_id INTEGER REFERENCES analyses(id) ON DELETE CASCADE,
    event_time  TEXT,                            -- heure de l'événement dans le journal
    username    TEXT,                            -- compte(s) visé(s)
    ip          TEXT,                            -- adresse IP source
    event       TEXT,                            -- login, sudo, account_created, group_add...
    severity    VARCHAR(10),                     -- CRITICAL, HIGH, MEDIUM, LOW
    reason      TEXT,                            -- explication lisible de l'alerte
    created_at  TIMESTAMP DEFAULT NOW()
);

-- ---------------------------------------------------------------------
-- 4. Index pour accélérer l'historique et les filtres
-- ---------------------------------------------------------------------
-- (mêmes tables et index que SCHEMA dans db.py, créés aussi au lancement de l'app)
CREATE INDEX IF NOT EXISTS idx_alerts_analysis  ON alerts (analysis_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_created   ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses (created_at DESC);
