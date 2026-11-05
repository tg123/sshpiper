fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = match std::env::var_os("PROTOC") {
        Some(path) => path.into(),
        None => protoc_bin_vendored::protoc_bin_path()?,
    };
    let mut config = tonic_prost_build::Config::new();
    config.protoc_executable(protoc);
    tonic_prost_build::configure().compile_with_config(
        config,
        &[
            "../../libplugin/plugin.proto",
            "../../libplugin/connovergrpc/connovergrpc.proto",
            "../../libadmin/admin.proto",
            "proto/signer.proto",
        ],
        &["../..", "proto"],
    )?;
    for file in [
        "../../libplugin/plugin.proto",
        "../../libplugin/connovergrpc/connovergrpc.proto",
        "../../libadmin/admin.proto",
        "proto/signer.proto",
    ] {
        println!("cargo:rerun-if-changed={file}");
    }
    println!("cargo:rerun-if-env-changed=PROTOC");
    Ok(())
}
