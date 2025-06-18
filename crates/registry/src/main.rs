use clap::Parser;
use opentelemetry::metrics::MeterProvider;
use opentelemetry::trace::{Tracer, TracerProvider as _};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::SdkTracerProvider;
use tracing::{error, info, span};
use tracing_subscriber::Registry;
use tracing_subscriber::layer::SubscriberExt;

#[derive(Parser)]
#[command(version, about)]
struct Args {}

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

    if let Err(err) = registry::http_listener(8080).await {
        panic!("Could not start registry: {err}");
    }

    tokio::signal::ctrl_c().await?;

    Ok(())
}
