use tonic_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &[
                "proto/gateway_worker.proto",
                "proto/certificate.proto",
                "proto/configuration.proto",
                "proto/log_processing.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}