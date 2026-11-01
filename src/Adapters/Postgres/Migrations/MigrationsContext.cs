using Microsoft.EntityFrameworkCore;

namespace Gatekeep.Adapters.Postgres.Migrations;

/// <summary>
/// Carries the migrations only. Its model is empty and there's no snapshot, because
/// migrations are hand-written SQL.
/// </summary>
public sealed class MigrationsContext(DbContextOptions<MigrationsContext> options) : DbContext(options);
