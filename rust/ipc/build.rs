// Build script to compile Cap'n Proto schema

fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/msf.capnp")
        .run()
        .expect("Failed to compile Cap'n Proto schema");
}
