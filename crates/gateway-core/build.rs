use tonic_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[
                "../gateway-worker/proto/gateway_worker.proto",
                "../gateway-worker/proto/certificate.proto",
                "../gateway-worker/proto/configuration.proto",
                "../gateway-worker/proto/log_processing.proto",
            ],
            &["../gateway-worker/proto"],
        )?;
    Ok(())
}