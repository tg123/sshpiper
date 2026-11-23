pub mod plugin {
    tonic::include_proto!("libplugin");
}
pub mod connection {
    tonic::include_proto!("connovergrpc");
}
pub mod signer {
    tonic::include_proto!("grpcsigner");
}
pub mod admin {
    tonic::include_proto!("libadmin");
}
