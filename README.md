# Bridge Starter Node

A starter service for bridging assets between Stellar and EVM chains, including
payouts, Soroban contract calls, webhook handling, and database-backed state.

## Database connection budget

The service uses `pg` connection pools for the primary and write databases. Pool
sizes are configured through environment variables and are validated at startup
so that the aggregate connection count stays within a safe budget for your
PostgreSQL deployment.

### Defaults

| Setting | Env var | Default |
| --- | --- | --- |
| Primary pool max | `DB_POOL_MAX` | `10` |
| Write pool max | `DB_WRITE_POOL_MAX` | `5` |
| App instances | `DB_APP_INSTANCES` | `1` |
| Replicas per pool | `DB_REPLICAS` | `0` |
| Connection budget | `DB_CONNECTION_BUDGET` | `100` |

### Startup validation

At startup the service computes the aggregate pool sizing:

```
aggregate = (DB_POOL_MAX + DB_WRITE_POOL_MAX) * (DB_REPLICAS + 1) * DB_APP_INSTANCES
```

If `aggregate` exceeds `DB_CONNECTION_BUDGET`, the service logs a warning and
fails fast so a misconfigured deployment cannot exhaust PostgreSQL connections.
Tune the budget to match your PostgreSQL `max_connections` (leaving headroom for
admin, migration, and monitoring connections).

### PgBouncer interaction

When running behind PgBouncer, size pools against the PgBouncer pool, not the
raw PostgreSQL `max_connections`:

- **Transaction pooling** (recommended): server-side connections are shared per
transaction, so application pool sizes can be larger. Set
  `DB_CONNECTION_BUDGET` to the PgBouncer `max_db_connections` (or
  `default_pool_size` × databases) rather than PostgreSQL `max_connections`.
- **Session pooling**: each client holds a server connection for the session
  lifetime, so the aggregate application pool sizing must fit within the
  PgBouncer server pool. Keep `DB_POOL_MAX` and `DB_WRITE_POOL_MAX` conservative
  and set `DB_CONNECTION_BUDGET` to the PgBouncer server pool size.

Avoid mixing transaction pooling with session-level features (prepared
statements, advisory locks held across statements) unless PgBouncer is
configured to support them.
