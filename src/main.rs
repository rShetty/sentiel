use std::sync::Arc;

use clap::{Parser, Subcommand};

use sentiel::{
    anomaly::AnomalyEngine,
    auth::AuthConfig,
    config::Config,
    db::Database,
    dlp::DlpEngine,
    server::{self, AppState},
};

#[derive(Parser)]
#[command(name = "sentiel")]
#[command(about = "Observability, DLP, and compliance for AI agent ecosystems")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Serve {
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    Init,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentiel=info".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            let config = Config::default();
            let toml = toml::to_string_pretty(&config)?;
            std::fs::write("config.toml", toml)?;
            println!("Created config.toml");
        }
        Commands::Serve { config } => {
            let config = Config::load(&config).unwrap_or_default();

            // Startup guard: release builds refuse to run without API tokens
            // unless SENTIEL_INSECURE_DEV=1 was set explicitly.
            let auth = AuthConfig::from_env();
            if let Err(message) = auth.ensure_startable(cfg!(not(debug_assertions))) {
                eprintln!("sentiel: {message}");
                anyhow::bail!(message);
            }

            let db = Database::new(&config.database.path)?;
            let state = AppState {
                db: Arc::new(db),
                dlp: Arc::new(DlpEngine::new(config.dlp.enabled)),
                anomaly: Arc::new(AnomalyEngine::new(config.anomaly.clone())),
                config: Arc::new(config.clone()),
                auth: Arc::new(auth),
            };

            let app = server::create_router(state);
            let addr = format!("{}:{}", config.server.host, config.server.port);
            tracing::info!("Sentiel starting on {}", addr);

            let listener = tokio::net::TcpListener::bind(&addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}
