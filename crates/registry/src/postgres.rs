use deadpool_postgres::{ManagerConfig, PoolConfig, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;
use tracing::info;

/// DB allows operations on a (remote) postgres database server
#[derive(Clone)]
pub struct DB {
    pool: deadpool_postgres::Pool,
}

/// Options used to connect to the database.
pub struct ConnectionOptions {
    /// User to authenticate with
    pub user: String,
    /// Password to authenticate with
    pub password: String,
    /// Name of the datbase to open
    pub db_name: String,
    /// Host of the database server
    pub host: String,
    /// Port the database server is listening on
    pub port: u16,
}

impl DB {
    /// Create a new connection to a postgres database, and runs required migrations.
    #[tracing::instrument(skip_all)]
    pub async fn new(opts: ConnectionOptions) -> Result<Self, Box<dyn std::error::Error>> {
        let mut cfg = deadpool_postgres::Config::new();
        cfg.user = Some(opts.user);
        cfg.password = Some(opts.password);
        cfg.dbname = Some(opts.db_name);
        cfg.host = Some(opts.host);
        cfg.port = Some(opts.port);
        cfg.manager = Some(ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        });

        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls)?;

        let pool_status = pool.status();
        info!(
            pool.max_connections = pool_status.max_size,
            "Postgres connection pool created"
        );

        let db = DB { pool };

        db.migrate_v1().await?;

        Ok(db)
    }

    /// Load the blob data of a blob identified by `hash`
    #[tracing::instrument(skip_all)]
    pub async fn load_blob(
        &self,
        hash: [u8; 32],
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        let stmt = client
            .prepare("SELECT data FROM blobs WHERE hash = $1")
            .await?;
        let rows = client.query(&stmt, &[&&hash[..]]).await?;

        Ok(if let Some(row) = rows.first() {
            let data: Vec<u8> = row.get(0);
            Some(data)
        } else {
            None
        })
    }

    /// Runs the migrations which sets up the initial table structure.
    #[tracing::instrument(skip_all)]
    async fn migrate_v1(&self) -> Result<(), Box<dyn std::error::Error>> {
        let client = self.pool.get().await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS blobs (
                hash BYTEA PRIMARY KEY,
                data BYTEA NOT NULL,
                size BIGINT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
            )
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
                CREATE INDEX IF NOT EXISTS idx_blobs_created_at ON blobs(created_at)
            "#,
                &[],
            )
            .await?;

        client
            .execute(
                r#"
            CREATE TABLE IF NOT EXISTS blob_access_stats (
                hash BYTEA REFERENCES blobs(hash) ON DELETE CASCADE,
                access_count BIGINT DEFAULT 0,
                last_accessed TIMESTAMP WITH TIME ZONE,
                PRIMARY KEY (hash)
            )
            "#,
                &[],
            )
            .await?;

        client.execute(
            r#"
                CREATE INDEX IF NOT EXISTS idx_blobs_last_accessed_at ON blob_access_stats(last_accessed)
            "#, &[]).await?;

        Ok(())
    }
}
