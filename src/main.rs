#[tokio::main]
async fn main() {
    if let Err(error) = zbierak::run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
