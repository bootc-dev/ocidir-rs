//! # Import a pre-generated tarball, wrapping with OCI metadata into an OCI directory.
//!
//! This little exmaple shows a bit of how to use the ocidir API. But it has a use case
//! for low-level testing of OCI runtimes by injecting arbitrary tarballs.

use std::io::BufReader;
use std::{fs::File, path::Path};

use anyhow::Context;
use cap_tempfile::cap_std;
use chrono::Utc;
use oci_spec::image::{MediaType, Platform};
use ocidir::OciDir;

fn import(oci_dir: &OciDir, name: &str, src: File) -> anyhow::Result<()> {
    let mtime = src.metadata()?.modified()?;
    let mut input_tar = BufReader::new(src);
    let created = chrono::DateTime::<Utc>::from(mtime);

    let mut manifest = oci_dir.new_empty_manifest().unwrap().build().unwrap();
    let mut config = ocidir::oci_spec::image::ImageConfigurationBuilder::default()
        .build()
        .unwrap();

    // Add the src as a layer
    let mut writer = oci_dir.create_blob().unwrap();
    std::io::copy(&mut input_tar, &mut writer)?;

    let blob = writer.complete()?;
    let descriptor = blob
        .descriptor()
        .media_type(MediaType::ImageLayer)
        .build()
        .unwrap();
    let blob_digest = descriptor.digest().to_string();
    manifest.layers_mut().push(descriptor);
    let mut rootfs = config.rootfs().clone();
    rootfs.diff_ids_mut().push(blob_digest);
    config.set_rootfs(rootfs);
    let h = oci_spec::image::HistoryBuilder::default()
        .created(created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .created_by(name.to_string())
        .build()
        .unwrap();
    match config.history_mut() {
        Some(v) => v.push(h),
        None => {
            config.set_history(Some(vec![h]));
        }
    }

    println!(
        "Created image with manifest: {}",
        manifest.to_string_pretty().unwrap()
    );

    // Add the image manifest
    let _descriptor = oci_dir
        .insert_manifest_and_config(
            manifest.clone(),
            config,
            Some("latest"),
            Platform::default(),
        )
        .unwrap();

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = std::env::args().collect::<Vec<_>>();
    let ocidir = args[1].as_str();
    let path = Path::new(args[2].as_str());
    let Some(name) = path.file_stem().and_then(|v| v.to_str()) else {
        anyhow::bail!("Invalid path: {path:?}");
    };
    let f = File::open(path).with_context(|| format!("Opening {path:?}"))?;

    let dir = &cap_std::fs::Dir::open_ambient_dir(ocidir, cap_std::ambient_authority())
        .with_context(|| format!("Opening {ocidir}"))?;
    let oci_dir = OciDir::ensure(dir.try_clone()?)?;

    import(&oci_dir, name, f)?;
    Ok(())
}
