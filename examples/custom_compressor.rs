/// Example that shows how to use a custom compression and media type for image layers.
/// The example below does no compression.
use std::{env, io, path::PathBuf};

use oci_spec::image::Platform;
use ocidir::{BlobWriter, OciDir, WriteComplete, cap_std::fs::Dir};

struct NoCompression<'a>(BlobWriter<'a>);

impl io::Write for NoCompression<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<'a> WriteComplete<BlobWriter<'a>> for NoCompression<'a> {
    fn complete(self) -> io::Result<BlobWriter<'a>> {
        Ok(self.0)
    }
}

fn main() {
    let dir = Dir::open_ambient_dir(env::temp_dir(), ocidir::cap_std::ambient_authority()).unwrap();
    let oci_dir = OciDir::ensure(dir).unwrap();

    let mut manifest = oci_dir.new_empty_manifest().unwrap().build().unwrap();
    let mut config = ocidir::oci_spec::image::ImageConfigurationBuilder::default()
        .build()
        .unwrap();

    // Add the src as a layer
    let writer = oci_dir
        .create_custom_layer(
            |bw| Ok(NoCompression(bw)),
            oci_spec::image::MediaType::ImageLayer,
        )
        .unwrap();
    let mut builder = tar::Builder::new(writer);
    builder.follow_symlinks(false);

    builder
        .append_dir_all(".", PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"))
        .unwrap();

    let layer = builder.into_inner().unwrap().complete().unwrap();
    oci_dir.push_layer(&mut manifest, &mut config, layer, "src", None);

    println!(
        "Created image with manifest: {}",
        manifest.to_string_pretty().unwrap()
    );

    // Add the image manifest
    let _descriptor = oci_dir
        .insert_manifest_and_config(manifest.clone(), config, None, Platform::default())
        .unwrap();
}
