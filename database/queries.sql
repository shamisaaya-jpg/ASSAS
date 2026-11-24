-- =====================================================================
-- ASSAS - Requêtes utiles (PostgreSQL)
-- Exécution :
--   docker exec -i assas-postgres psql -U assas -d assas < database/queries.sql
-- ou une requête à la fois dans :
--   docker exec -it assas-postgres psql -U assas -d assas
-- =====================================================================

-- 1. Historique des analyses, de la plus récente à la plus ancienne
SELECT a.id, a.created_at, a.filename, u.username AS analyste,
       a.total, a.critical, a.high, a.medium, a.low
FROM analyses a
LEFT JOIN users u ON u.id = a.analyzed_by
ORDER BY a.created_at DESC;

-- 2. Toutes les alertes critiques
SELECT al.event_time, al.username, al.ip, al.event, al.reason, an.filename
FROM alerts al
JOIN analyses an ON an.id = al.analysis_id
WHERE al.severity = 'CRITICAL'
ORDER BY al.created_at DESC;

-- 3. Nombre d'alertes par niveau de gravité
SELECT severity, COUNT(*) AS nombre
FROM alerts
GROUP BY severity
ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                       WHEN 'MEDIUM' THEN 2 ELSE 3 END;

-- 4. Les 5 adresses IP qui déclenchent le plus d'alertes
SELECT ip, COUNT(*) AS alertes
FROM alerts
WHERE ip <> ''
GROUP BY ip
ORDER BY alertes DESC
LIMIT 5;

-- 5. Comptes compromis ou backdoors détectés
SELECT event_time, username, ip, reason
FROM alerts
WHERE reason ILIKE '%compromised%' OR reason ILIKE '%backdoor%'
ORDER BY event_time;

-- 6. Administrateurs enregistrés (sans les mots de passe)
SELECT id, username, created_at FROM users ORDER BY id;
