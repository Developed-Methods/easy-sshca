SELECT
    z.id,
    z.name,
    '',
    z.max_duration,
    z.active,
    0,
    z.fingerprint
FROM zones AS z
JOIN user_zones AS g ON g.zone_id = z.id
JOIN users AS u ON u.id = g.user_id
WHERE z.id > ?1
  AND u.name = ?3
  AND u.removed = 0
ORDER BY z.id
LIMIT ?2
