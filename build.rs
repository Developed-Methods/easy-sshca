fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc_bin_vendored::protoc_bin_path()?);
    config.skip_debug([".easysshca.v1.Command", ".easysshca.v1.Reply"]);
    config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
    tonic_prost_build::configure().compile_with_config(
        config,
        &["proto/easysshca/v1/ca.proto"],
        &["proto"],
    )?;
    println!("cargo:rerun-if-changed=proto/easysshca/v1/ca.proto");
    Ok(())
}
