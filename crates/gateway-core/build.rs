use tonic_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[
                "proto/gateway_worker.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}