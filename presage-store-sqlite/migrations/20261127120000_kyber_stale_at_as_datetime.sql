UPDATE kyber_pre_keys
SET stale_at = strftime('%Y-%m-%d %H:%M:%f', stale_at / 1000.0, 'unixepoch')
WHERE typeof(stale_at) = 'integer';
