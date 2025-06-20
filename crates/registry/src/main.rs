use clap::Parser;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::trace::{Tracer, TracerProvider as _};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use registry::postgres::ConnectionOptions;
use tracing::{error, info, span};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt;

/// Default name of the database used in the server.
const DEFAULT_DB_NAME: &str = "mycelium_cdn_registry";
/// Default hostname for the database connection.
const DEFAULT_DB_HOST: &str = "localhost";
/// Default listening port for the database.
const DEFAULT_DB_PORT: u16 = 5432;

#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Username of the user to authenticate to the database with.
    #[arg(long)]
    db_user: String,
    /// Password of the user to authenticate to the database with.
    #[arg(long)]
    db_password: String,
    /// Name of the database at the database server to connect to.
    #[arg(long, default_value = DEFAULT_DB_NAME)]
    db_name: String,
    /// Hostname of the database server to connect to.
    #[arg(long, default_value = DEFAULT_DB_HOST)]
    db_host: String,
    /// Port the database server is listening on.
    #[arg(long, default_value_t = DEFAULT_DB_PORT)]
    db_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let provider = SdkTracerProvider::builder()
        .with_simple_exporter(opentelemetry_stdout::SpanExporter::default())
        .build();
    let tracer = provider.tracer("mycelium-cdn-registry");
    // let provider = SdkMeterProvider::builder().with_resource
    // let meter = provider.meter();

    let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

    let subscriber = Registry::default().with(telemetry);

    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        panic!("Could not install global tracing subscriber: {err}");
    }

    let db = registry::postgres::DB::new(ConnectionOptions {
        user: args.db_user,
        password: args.db_password,
        db_name: args.db_name,
        host: args.db_host,
        port: args.db_port,
    })
    .await?;

    if let Err(err) = registry::http_listener(8080, db).await {
        panic!("Could not start registry: {err}");
    }

    tokio::signal::ctrl_c().await?;

    Ok(())
}
