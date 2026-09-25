//! Zbierak server binary: runs the operator UI and the versioned ingestion
//! API until shut down.

#[tokio::main]
async fn main() {
    if let Err(error) = zbierak::run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
