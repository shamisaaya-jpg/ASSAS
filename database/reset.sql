-- =====================================================================
-- ASSAS - Remise à zéro avant une démonstration
-- Efface l'historique des analyses et des alertes.
-- Les comptes administrateurs (table users) sont conservés.
--
--   docker exec -i assas-postgres psql -U assas -d assas < database/reset.sql
--
-- Pour vider aussi les logs stockés dans OpenSearch :
--   curl -X DELETE http://localhost:9200/assas-logs
-- =====================================================================

TRUNCATE alerts, analyses RESTART IDENTITY;
