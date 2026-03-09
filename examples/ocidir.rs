//! CLI tool demonstrating ocidir-rs capabilities: init, pull, push, inspect,
//! and a self-test that exercises the full API including OCI artifacts.

use std::io::Write;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use oci_distribution::Reference;
use oci_distribution::client::{ClientConfig, ClientProtocol, ImageData};
use oci_distribution::secrets::RegistryAuth;
use ocidir::OciDir;
use ocidir::cap_std::fs::Dir;
use ocidir::oci_spec::image::{self as oci_image, Descriptor, ImageManifest, MediaType, Platform};

const OCI_TAG_ANNOTATION: &str = "org.opencontainers.image.ref.name";

#[derive(Parser)]
#[command(name = "ocidir", about = "OCI directory management tool")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialise an empty OCI image layout directory
    Init {
        /// Path to the OCI directory to create
        path: String,
    },
    /// Pull an image from a registry or OCI directory into an OCI directory
    Pull {
        /// Path to the destination OCI directory
        path: String,
        /// Image reference (registry) or source OCI directory path (oci transport)
        image: String,
        /// Transport to use for pulling
        #[arg(long, default_value = "registry")]
        transport: Transport,
        /// Tag to pull (only used with --transport=oci)
        #[arg(long)]
        tag: Option<String>,
    },
    /// Push an image from an OCI directory to a registry or another OCI directory
    Push {
        /// Path to the source OCI directory
        path: String,
        /// Target image reference (registry) or destination OCI directory path (oci transport)
        image: String,
        /// Transport to use for pushing
        #[arg(long, default_value = "registry")]
        transport: Transport,
        /// Tag to push (only used with --transport=oci)
        #[arg(long)]
        tag: Option<String>,
    },
    /// Inspect an OCI directory (show index, manifests, blobs)
    Inspect {
        /// Path to the OCI directory
        path: String,
    },
    /// Run a self-test: pull busybox, create OCI artifacts, verify referrers, fsck
    Selftest,
}

/// Transport mechanism for pulling/pushing images.
#[derive(Clone, Debug, ValueEnum)]
enum Transport {
    /// Pull/push from/to a container registry (default)
    Registry,
    /// Pull/push from/to a local OCI image layout directory
    Oci,
}

/// Create an oci-distribution client configured for anonymous public access.
fn new_registry_client() -> oci_distribution::Client {
    let config = ClientConfig {
        protocol: ClientProtocol::Https,
        ..Default::default()
    };
    oci_distribution::Client::new(config)
}

/// Open an existing OCI directory at the given path.
fn open_ocidir(path: &str) -> Result<OciDir> {
    let dir = Dir::open_ambient_dir(path, ocidir::cap_std::ambient_authority())
        .with_context(|| format!("opening directory '{path}'"))?;
    OciDir::open(dir).context("opening OCI directory")
}

/// Create or open an OCI directory at the given path.
fn ensure_ocidir(path: &str) -> Result<OciDir> {
    std::fs::create_dir_all(path).with_context(|| format!("creating directory '{path}'"))?;
    let dir = Dir::open_ambient_dir(path, ocidir::cap_std::ambient_authority())
        .with_context(|| format!("opening directory '{path}'"))?;
    OciDir::ensure(dir).context("ensuring OCI directory")
}

/// Pull an image from the registry and store it in the OCI directory.
///
/// This bridges between oci-distribution's types and oci-spec's types by
/// using raw JSON manifest bytes and writing blobs individually.
async fn pull_image(image_ref: &str, ocidir: &OciDir) -> Result<Descriptor> {
    let client = new_registry_client();
    let reference: Reference = image_ref
        .parse()
        .with_context(|| format!("parsing image reference '{image_ref}'"))?;
    let auth = RegistryAuth::Anonymous;

    // Pull the full image (manifest + config + layers)
    let accepted_layer_types = vec![
        oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
        oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE,
        oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        oci_distribution::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    ];
    let ImageData {
        manifest: Some(manifest),
        config,
        layers,
        ..
    } = client
        .pull(&reference, &auth, accepted_layer_types)
        .await
        .context("pulling image")?
    else {
        anyhow::bail!("no manifest in pull response");
    };

    // Write config blob
    let config_data = config.data;
    let mut config_blob = ocidir.create_blob()?;
    config_blob.write_all(&config_data)?;
    let config_blob = config_blob.complete()?;
    let config_desc = config_blob
        .descriptor()
        .media_type(MediaType::ImageConfig)
        .build()?;

    // Write layer blobs and build descriptors
    let mut layer_descs = Vec::new();
    for (i, layer_data) in layers.iter().enumerate() {
        let mut blob = ocidir.create_blob()?;
        blob.write_all(&layer_data.data)?;
        let blob = blob.complete()?;

        // Map the media type from oci-distribution to oci-spec
        let media_type = map_media_type(&manifest.layers[i].media_type);
        let desc = blob.descriptor().media_type(media_type).build()?;
        layer_descs.push(desc);
    }

    // Build the oci-spec ImageManifest from the pulled data
    let oci_manifest = oci_image::ImageManifestBuilder::default()
        .schema_version(oci_image::SCHEMA_VERSION)
        .config(config_desc)
        .layers(layer_descs)
        .build()?;

    let tag = reference.tag().unwrap_or("latest");
    let desc = ocidir.insert_manifest(oci_manifest, Some(tag), Platform::default())?;

    println!("Pulled {image_ref} -> {}", desc.digest());
    Ok(desc)
}

/// Push an image from the OCI directory to a registry.
async fn push_image(ocidir: &OciDir, image_ref: &str) -> Result<()> {
    let client = new_registry_client();
    let reference: Reference = image_ref
        .parse()
        .with_context(|| format!("parsing image reference '{image_ref}'"))?;
    let auth = RegistryAuth::Anonymous;

    let resolved = ocidir
        .open_image_this_platform(None)
        .context("resolving manifest for this platform")?;
    let manifest = &resolved.manifest;

    // Read config blob
    let config_data = {
        let mut f = ocidir.read_blob(manifest.config())?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut buf)?;
        buf
    };

    // Build oci-distribution layers.
    // Note: this reads entire layers into memory, which is fine for small
    // images but production code should stream where possible.
    let mut layers = Vec::new();
    for layer_desc in manifest.layers() {
        let mut f = ocidir.read_blob(layer_desc)?;
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut buf)?;
        layers.push(oci_distribution::client::ImageLayer::new(
            buf,
            layer_desc.media_type().to_string(),
            None,
        ));
    }

    let config = oci_distribution::client::Config::oci_v1(config_data, None);

    let push_response = client
        .push(&reference, &layers, config, &auth, None)
        .await
        .context("pushing image")?;

    println!("Pushed to {}", push_response.manifest_url);
    Ok(())
}

/// Copy manifests (and all referenced blobs) between two OCI directories.
///
/// If `tag` is specified, only the manifest with that tag is copied.
/// Otherwise, the entire source index is copied.  All referenced blobs
/// (config, layers, artifact content) are copied using content-addressed
/// writes so duplicates are automatically deduplicated.
fn copy_ocidir(src: &OciDir, dest: &OciDir, tag: Option<&str>) -> Result<usize> {
    let src_index = src.read_index().context("reading source index")?;

    let descs: Vec<_> = if let Some(tag) = tag {
        src_index
            .manifests()
            .iter()
            .filter(|d| descriptor_tag(d) == Some(tag))
            .cloned()
            .collect()
    } else {
        src_index.manifests().clone()
    };

    if descs.is_empty() {
        if let Some(tag) = tag {
            anyhow::bail!("tag '{tag}' not found in source OCI directory");
        }
        anyhow::bail!("source OCI directory has no manifests");
    }

    for desc in &descs {
        copy_manifest_tree(src, dest, desc)?;
    }

    Ok(descs.len())
}

/// Copy from a source OCI directory to a destination OCI directory.
fn pull_from_ocidir(source_path: &str, tag: Option<&str>, dest: &OciDir) -> Result<()> {
    let src = open_ocidir(source_path)?;
    let count = copy_ocidir(&src, dest, tag)?;
    println!("Copied {count} manifest(s) from {source_path}");
    Ok(())
}

/// Push from a source OCI directory to a destination OCI directory.
fn push_to_ocidir(src: &OciDir, dest_path: &str, tag: Option<&str>) -> Result<()> {
    let dest = ensure_ocidir(dest_path)?;
    let count = copy_ocidir(src, &dest, tag)?;
    println!("Pushed {count} manifest(s) to {dest_path}");
    Ok(())
}

/// Return the tag annotation from a descriptor, if present.
fn descriptor_tag(desc: &Descriptor) -> Option<&str> {
    desc.annotations()
        .as_ref()
        .and_then(|a| a.get(OCI_TAG_ANNOTATION))
        .map(|s| s.as_str())
}

/// Recursively copy a manifest and all its referenced blobs from `src` to
/// `dest`.
///
/// For image manifests, this copies config + layers, then calls
/// `insert_manifest` (or `insert_artifact_manifest` for artifacts with
/// `subject`) which writes the manifest blob and updates the index.
///
/// For image indices (manifest lists), the children are recursively copied.
/// The manifest list structure itself is not preserved in the destination
/// index — child manifests are inserted individually. This is sufficient
/// for the common case where `oci-distribution` has already resolved to
/// platform-specific manifests.
fn copy_manifest_tree(src: &OciDir, dest: &OciDir, desc: &Descriptor) -> Result<()> {
    match desc.media_type() {
        MediaType::ImageManifest => {
            let manifest: ImageManifest = src.read_json_blob(desc)?;

            // Copy config blob
            copy_blob_if_needed(src, dest, manifest.config())?;

            // Copy layer blobs
            for layer in manifest.layers() {
                copy_blob_if_needed(src, dest, layer)?;
            }

            // Copy subject blob if present (the subject manifest should
            // already exist if the index is well-ordered, but copy it
            // defensively to avoid broken references)
            if let Some(subject) = manifest.subject() {
                copy_blob_if_needed(src, dest, subject)?;
            }

            if let Some(subject) = manifest.subject().clone() {
                // Artifact manifest: use insert_artifact_manifest so the
                // descriptor omits platform (artifacts are not
                // platform-specific)
                let artifact_type = manifest
                    .artifact_type()
                    .clone()
                    .unwrap_or_else(|| manifest.config().media_type().clone());

                let annotations = manifest.annotations().clone();

                dest.insert_artifact_manifest(
                    subject,
                    artifact_type,
                    manifest.layers().clone(),
                    annotations,
                )?;
            } else {
                // Regular image manifest: insert_manifest writes the
                // manifest blob and adds it to the index
                let tag = descriptor_tag(desc);
                let platform = desc.platform().clone().unwrap_or_default();
                dest.insert_manifest(manifest, tag, platform)?;
            }
        }
        MediaType::ImageIndex => {
            let nested: oci_image::ImageIndex = src.read_json_blob(desc)?;

            // Recursively copy all child manifests; the manifest list
            // structure is flattened into individual index entries.
            for child in nested.manifests() {
                copy_manifest_tree(src, dest, child)?;
            }
        }
        other => {
            // Copy the blob and warn about the unexpected media type
            copy_blob_if_needed(src, dest, desc)?;
            eprintln!(
                "warning: skipping unknown media type {} for {}",
                other,
                desc.digest()
            );
        }
    }
    Ok(())
}

/// Copy a single blob from `src` to `dest` if it doesn't already exist.
fn copy_blob_if_needed(src: &OciDir, dest: &OciDir, desc: &Descriptor) -> Result<()> {
    if dest.has_blob(desc)? {
        return Ok(());
    }
    let mut reader = std::io::BufReader::new(src.read_blob(desc)?);
    let mut writer = dest.create_blob()?;
    std::io::copy(&mut reader, &mut writer)?;
    writer.complete_verified_as(desc)?;
    Ok(())
}

/// Map an oci-distribution media type string to an oci-spec MediaType.
fn map_media_type(media_type: &str) -> MediaType {
    match media_type {
        "application/vnd.oci.image.layer.v1.tar+gzip" => MediaType::ImageLayerGzip,
        "application/vnd.oci.image.layer.v1.tar" => MediaType::ImageLayer,
        "application/vnd.oci.image.layer.v1.tar+zstd" => MediaType::ImageLayerZstd,
        "application/vnd.docker.image.rootfs.diff.tar.gzip" => MediaType::ImageLayerGzip,
        other => MediaType::Other(other.to_string()),
    }
}

/// Inspect an OCI directory: print index entries and manifest details.
fn inspect(ocidir: &OciDir) -> Result<()> {
    let index = match ocidir.read_index() {
        Ok(idx) => idx,
        Err(ocidir::Error::MissingImageIndex) => {
            println!("Empty OCI directory (no index.json yet)");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    println!("Index schema version: {}", index.schema_version());
    println!("Manifests: {}", index.manifests().len());

    for (i, desc) in index.manifests().iter().enumerate() {
        println!("\n  [{i}] digest: {}", desc.digest());
        println!("      media_type: {}", desc.media_type());
        println!("      size: {}", desc.size());
        if let Some(at) = desc.artifact_type() {
            println!("      artifact_type: {at}");
        }
        if let Some(platform) = desc.platform() {
            println!(
                "      platform: {}/{}",
                platform.os(),
                platform.architecture()
            );
        }
        if let Some(annos) = desc.annotations() {
            for (k, v) in annos {
                println!("      annotation: {k}={v}");
            }
        }

        // Best-effort display of manifest details; skip if the blob
        // can't be read (e.g. external blobs, truncated layout).
        if desc.media_type() == &MediaType::ImageManifest
            && let Ok(manifest) = ocidir.read_json_blob::<ImageManifest>(desc)
        {
            println!(
                "      config: {} ({})",
                manifest.config().digest(),
                manifest.config().media_type()
            );
            println!("      layers: {}", manifest.layers().len());
            if let Some(subject) = manifest.subject() {
                println!("      subject: {}", subject.digest());
            }
            if let Some(at) = manifest.artifact_type() {
                println!("      manifest artifact_type: {at}");
            }
        }
    }

    Ok(())
}

/// Descriptor from the OCI Referrers API response. This extends the
/// standard OCI descriptor with `artifactType`, which oci-distribution's
/// types don't yet include (it predates OCI 1.1).
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReferrerDescriptor {
    media_type: String,
    digest: String,
    #[allow(dead_code)]
    size: i64,
    artifact_type: Option<String>,
    #[serde(default)]
    annotations: Option<std::collections::HashMap<String, String>>,
}

/// Response from the OCI Referrers API endpoint.
#[derive(Debug, serde::Deserialize)]
struct ReferrersResponse {
    manifests: Vec<ReferrerDescriptor>,
}

/// Discover cosign-style referrer tags for a given manifest digest.
///
/// Cosign stores signatures, attestations, and SBOMs using a tag-based
/// convention: `sha256-<hex>.<suffix>` where suffix is `sig`, `att`, or
/// `sbom`. This function lists tags in the repository and returns matching
/// referrer tags grouped by suffix.
async fn discover_cosign_tags(
    registry: &str,
    repo: &str,
    digest: &str,
) -> Result<Vec<(String, String)>> {
    let client = new_registry_client();
    let image_ref: Reference = format!("{registry}/{repo}:latest").parse()?;
    let auth = RegistryAuth::Anonymous;

    let tag_response = client
        .list_tags(&image_ref, &auth, None, None)
        .await
        .context("listing tags")?;

    // Strip the sha256: prefix for the tag lookup
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    let prefix = format!("sha256-{hex}");

    let mut referrer_tags = Vec::new();
    for tag in &tag_response.tags {
        if let Some(suffix) = tag.strip_prefix(&format!("{prefix}.")) {
            referrer_tags.push((tag.clone(), suffix.to_string()));
        }
    }

    Ok(referrer_tags)
}

/// Pull a cosign referrer manifest from the registry and store it as an
/// OCI artifact in the local directory, with `subject` pointing to the
/// referenced image manifest.
///
/// This converts from the legacy cosign tag-based convention to the modern
/// OCI Referrers model.
async fn pull_cosign_referrer(
    registry: &str,
    repo: &str,
    tag: &str,
    suffix: &str,
    subject: &Descriptor,
    ocidir: &OciDir,
) -> Result<Descriptor> {
    let client = new_registry_client();
    let image_ref: Reference = format!("{registry}/{repo}:{tag}").parse()?;
    let auth = RegistryAuth::Anonymous;

    // Pull the raw manifest bytes
    let (manifest_bytes, _digest) = client
        .pull_manifest_raw(
            &image_ref,
            &auth,
            &[oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE],
        )
        .await
        .with_context(|| format!("pulling manifest for tag '{tag}'"))?;

    // Parse into oci-distribution's OciImageManifest to access layer descriptors
    let dist_manifest: oci_distribution::manifest::OciImageManifest =
        serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("parsing manifest for tag '{tag}'"))?;

    // Write config blob
    let config_desc = &dist_manifest.config;
    let mut config_data = Vec::new();
    client
        .pull_blob(&image_ref, config_desc, &mut config_data)
        .await
        .context("pulling config blob")?;
    let mut config_blob = ocidir.create_blob()?;
    config_blob.write_all(&config_data)?;
    let _config_blob = config_blob.complete()?;

    // Write layer blobs
    let mut layer_descs = Vec::new();
    for layer in &dist_manifest.layers {
        let mut layer_data = Vec::new();
        client
            .pull_blob(&image_ref, layer, &mut layer_data)
            .await
            .context("pulling layer blob")?;
        let mut blob = ocidir.create_blob()?;
        blob.write_all(&layer_data)?;
        let blob = blob.complete()?;
        let desc = blob
            .descriptor()
            .media_type(MediaType::Other(layer.media_type.clone()))
            .annotations(layer.annotations.clone().unwrap_or_default())
            .build()?;
        layer_descs.push(desc);
    }

    // Map the cosign suffix to an artifact type
    let artifact_type = match suffix {
        "sig" => MediaType::Other("application/vnd.dev.cosign.simplesigning.v1+json".into()),
        "att" => MediaType::Other("application/vnd.dsse.envelope.v1+json".into()),
        "sbom" => MediaType::Other("application/spdx+json".into()),
        other => MediaType::Other(format!("application/vnd.cosign.{other}")),
    };

    // Store as a proper OCI artifact with subject
    let desc =
        ocidir.insert_artifact_manifest(subject.clone(), artifact_type, layer_descs, None)?;

    Ok(desc)
}

/// Query the OCI Referrers API for a given manifest digest on Docker Hub.
///
/// Returns the list of referrer descriptors from the referrers index.
/// This handles Docker Hub's anonymous token auth directly since
/// oci-distribution does not expose a referrers API method.
async fn query_dockerhub_referrers(repo: &str, digest: &str) -> Result<Vec<ReferrerDescriptor>> {
    let http_client = reqwest::Client::new();

    // Get anonymous bearer token
    let token_url = format!(
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
    );
    let token_resp: serde_json::Value = http_client.get(&token_url).send().await?.json().await?;
    let token = token_resp["token"]
        .as_str()
        .context("missing token in auth response")?;

    // Query the referrers endpoint
    let referrers_url = format!("https://registry-1.docker.io/v2/{repo}/referrers/{digest}");
    let resp = http_client
        .get(&referrers_url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .context("querying referrers API")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "referrers API returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    let index: ReferrersResponse = resp.json().await.context("parsing referrers index")?;

    Ok(index.manifests)
}

/// Pull a referrer artifact manifest from Docker Hub by digest and store
/// it as an OCI artifact in the local directory.
async fn pull_referrer_artifact(
    repo: &str,
    referrer_desc: &ReferrerDescriptor,
    subject: &Descriptor,
    ocidir: &OciDir,
) -> Result<Descriptor> {
    let client = new_registry_client();
    let auth = RegistryAuth::Anonymous;
    let image_ref: Reference = format!("docker.io/{repo}@{}", referrer_desc.digest)
        .parse()
        .context("parsing referrer reference")?;

    // Pull the raw manifest
    let (manifest_bytes, _digest) = client
        .pull_manifest_raw(
            &image_ref,
            &auth,
            &[oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE],
        )
        .await
        .context("pulling referrer manifest")?;

    let dist_manifest: oci_distribution::manifest::OciImageManifest =
        serde_json::from_slice(&manifest_bytes).context("parsing referrer manifest")?;

    // Write config blob
    let mut config_data = Vec::new();
    client
        .pull_blob(&image_ref, &dist_manifest.config, &mut config_data)
        .await
        .context("pulling referrer config blob")?;
    let mut config_blob = ocidir.create_blob()?;
    config_blob.write_all(&config_data)?;
    let _config_blob = config_blob.complete()?;

    // Write layer blobs
    let mut layer_descs = Vec::new();
    for layer in &dist_manifest.layers {
        let mut layer_data = Vec::new();
        client
            .pull_blob(&image_ref, layer, &mut layer_data)
            .await
            .context("pulling referrer layer blob")?;
        let mut blob = ocidir.create_blob()?;
        blob.write_all(&layer_data)?;
        let blob = blob.complete()?;
        let desc = blob
            .descriptor()
            .media_type(MediaType::Other(layer.media_type.clone()))
            .annotations(layer.annotations.clone().unwrap_or_default())
            .build()?;
        layer_descs.push(desc);
    }

    // Determine artifact type: prefer the descriptor's artifactType, fall
    // back to config.mediaType per the OCI spec.
    let artifact_type = MediaType::Other(
        referrer_desc
            .artifact_type
            .clone()
            .unwrap_or_else(|| dist_manifest.config.media_type.clone()),
    );

    let desc = ocidir.insert_artifact_manifest(
        subject.clone(),
        artifact_type,
        layer_descs,
        referrer_desc.annotations.clone(),
    )?;

    Ok(desc)
}

/// Self-test: exercises pulling a real image, creating artifacts with
/// referrers, verifying the Referrers API, and running fsck.
async fn selftest() -> Result<()> {
    let tempdir = cap_tempfile::TempDir::new(ocidir::cap_std::ambient_authority())
        .context("creating temp directory")?;
    let ocidir = OciDir::ensure(tempdir.try_clone()?)?;
    let path = "(tempdir)";

    println!("=== Self-test: OCI directory at {path} ===\n");

    // Step 1: Pull a small public image.
    // TODO: Copy fixture images to ghcr.io/bootc-dev to avoid Docker Hub
    // rate limits on shared GitHub Actions runner IPs.
    println!("--- Step 1: Pull docker.io/library/busybox:latest ---");
    let image_desc = pull_image("docker.io/library/busybox:latest", &ocidir).await?;
    println!("  Image descriptor: {}\n", image_desc.digest());

    // Verify the pulled image has expected structure
    let manifest: ImageManifest = ocidir.read_json_blob(&image_desc)?;
    assert!(
        !manifest.layers().is_empty(),
        "busybox should have at least one layer"
    );
    println!(
        "  Manifest has {} layer(s), config type: {}",
        manifest.layers().len(),
        manifest.config().media_type()
    );

    // Step 2: Create an SBOM artifact referencing the image
    println!("--- Step 2: Create SBOM artifact ---");
    let sbom_type = MediaType::Other("application/vnd.example.sbom.v1+json".into());
    let sbom_data = br#"{"packages": [{"name": "busybox", "version": "latest"}]}"#;

    let mut sbom_blob = ocidir.create_blob()?;
    sbom_blob.write_all(sbom_data)?;
    let sbom_blob = sbom_blob.complete()?;
    let sbom_layer = sbom_blob
        .descriptor()
        .media_type(MediaType::Other(
            "application/vnd.example.sbom.v1+json".into(),
        ))
        .build()?;

    let sbom_desc = ocidir.insert_artifact_manifest(
        image_desc.clone(),
        sbom_type.clone(),
        vec![sbom_layer],
        Some(
            [("org.example.format".into(), "json".into())]
                .into_iter()
                .collect(),
        ),
    )?;
    println!("  SBOM artifact: {}", sbom_desc.digest());
    assert_eq!(
        sbom_desc.artifact_type().as_ref(),
        Some(&sbom_type),
        "SBOM descriptor should carry artifact_type"
    );

    // Step 3: Create a signature artifact referencing the image
    println!("--- Step 3: Create signature artifact ---");
    let sig_type = MediaType::Other("application/vnd.example.signature.v1".into());

    let sig_desc = ocidir.insert_artifact_manifest(
        image_desc.clone(),
        sig_type.clone(),
        vec![], // no content layers — uses empty descriptor
        None,
    )?;
    println!("  Signature artifact: {}", sig_desc.digest());
    assert!(
        sig_desc.platform().is_none(),
        "artifact descriptor should not have platform"
    );

    // Step 4: Verify the Referrers API
    println!("--- Step 4: Verify Referrers API ---");
    let all_referrers = ocidir.find_referrers(image_desc.digest(), None)?;
    assert_eq!(
        all_referrers.len(),
        2,
        "should find 2 referrers for the image"
    );
    println!(
        "  Found {} referrer(s) for {}",
        all_referrers.len(),
        image_desc.digest()
    );

    // Filter by type
    let sbom_referrers = ocidir.find_referrers(image_desc.digest(), Some(&sbom_type))?;
    assert_eq!(sbom_referrers.len(), 1, "should find 1 SBOM referrer");
    println!("  SBOM referrers: {}", sbom_referrers.len());

    let sig_referrers = ocidir.find_referrers(image_desc.digest(), Some(&sig_type))?;
    assert_eq!(sig_referrers.len(), 1, "should find 1 signature referrer");
    println!("  Signature referrers: {}", sig_referrers.len());

    // Verify annotations were propagated
    let sbom_ref = &sbom_referrers[0];
    let annos = sbom_ref
        .annotations()
        .as_ref()
        .expect("should have annotations");
    assert_eq!(
        annos.get("org.example.format"),
        Some(&"json".to_string()),
        "SBOM annotation should be propagated to descriptor"
    );
    println!(
        "  SBOM annotation org.example.format={}",
        annos["org.example.format"]
    );

    // Step 5: OCI transport round-trip test (before pulling more images
    // to avoid tag collisions — UBI and bitnami also use "latest")
    println!("--- Step 5: OCI transport round-trip ---");
    {
        let dest_dir = cap_tempfile::TempDir::new(ocidir::cap_std::ambient_authority())
            .context("creating round-trip temp directory")?;
        let dest = OciDir::ensure(dest_dir.try_clone()?)?;

        // Copy the busybox image and its artifacts to a new OCI directory
        let count =
            copy_ocidir(&ocidir, &dest, None).context("copying OCI directory for round-trip")?;
        println!("  Copied {count} manifest(s) to destination");
        assert_eq!(
            count, 3,
            "should copy 3 manifests (busybox + SBOM + signature)"
        );

        // Verify fsck passes on the copy
        let dest_validated = dest.fsck()?;
        println!("  Destination fsck validated {dest_validated} blob(s)");

        // Verify referrers are preserved
        let dest_index = dest.read_index()?;
        let busybox_desc = dest_index
            .manifests()
            .iter()
            .find(|d| descriptor_tag(d) == Some("latest"))
            .context("busybox should have 'latest' tag in destination")?;

        let dest_referrers = dest.find_referrers(busybox_desc.digest(), None)?;
        assert_eq!(
            dest_referrers.len(),
            2,
            "destination should have 2 referrers for busybox"
        );
        println!(
            "  Destination has {} referrer(s) for busybox",
            dest_referrers.len()
        );

        // Verify artifact descriptors don't have platform set
        for r in &dest_referrers {
            assert!(
                r.platform().is_none(),
                "artifact descriptor should not have platform after copy"
            );
        }

        // Test tag-filtered copy
        let tag_dir = cap_tempfile::TempDir::new(ocidir::cap_std::ambient_authority())
            .context("creating tag-filtered temp directory")?;
        let tag_dest = OciDir::ensure(tag_dir.try_clone()?)?;
        let tag_count =
            copy_ocidir(&ocidir, &tag_dest, Some("latest")).context("copying with tag filter")?;
        assert_eq!(
            tag_count, 1,
            "tag-filtered copy should copy exactly 1 manifest"
        );
        println!("  Tag-filtered copy: {tag_count} manifest(s)");

        println!("  OCI transport round-trip passed");
    }

    // Step 6: Pull UBI10 and discover its cosign referrers
    println!("--- Step 6: Pull UBI10 and discover cosign referrers ---");
    let ubi_registry = "registry.access.redhat.com";
    let ubi_repo = "ubi10/ubi";
    // Use a specific build tag that is known to have cosign artifacts.
    // TODO: Copy fixture images to ghcr.io/bootc-dev to avoid depending
    // on external registries.
    let ubi_tag = "10.0-1754454962";
    let ubi_ref = format!("{ubi_registry}/{ubi_repo}:{ubi_tag}");
    let ubi_desc = pull_image(&ubi_ref, &ocidir).await?;
    println!("  UBI image: {}", ubi_desc.digest());

    // Discover cosign referrer tags for this image's manifest list digest
    let ubi_digest = ubi_desc.digest().to_string();
    let cosign_tags = discover_cosign_tags(ubi_registry, ubi_repo, &ubi_digest).await?;
    println!(
        "  Found {} cosign referrer tag(s) for {}",
        cosign_tags.len(),
        ubi_digest
    );

    // If we didn't find referrer tags for the single-platform manifest,
    // check the manifest list digest (the tag points at the index).
    // oci-distribution resolves manifest lists to a single platform, so
    // ubi_desc.digest() is for the platform-specific manifest. The cosign
    // tags reference the *index* digest, so let's discover for that too.
    let cosign_tags = if cosign_tags.is_empty() {
        // Fetch the manifest list digest directly
        let client = new_registry_client();
        let ref_parsed: Reference = ubi_ref.parse()?;
        let index_digest = client
            .fetch_manifest_digest(&ref_parsed, &RegistryAuth::Anonymous)
            .await
            .context("fetching manifest list digest")?;
        println!("  Manifest list digest: {index_digest}");
        let tags = discover_cosign_tags(ubi_registry, ubi_repo, &index_digest).await?;
        println!("  Found {} cosign referrer tag(s) for index", tags.len());
        tags
    } else {
        cosign_tags
    };

    assert!(
        !cosign_tags.is_empty(),
        "UBI 10.0-1754454962 should have cosign referrer tags"
    );

    // Pull and store each cosign referrer as a proper OCI artifact
    let mut cosign_referrer_count = 0;
    for (tag, suffix) in &cosign_tags {
        // Only process .sig and .att (skip duplicate .sbom entries etc.)
        if !["sig", "att"].contains(&suffix.as_str()) {
            println!("  Skipping {tag} (suffix: {suffix})");
            continue;
        }
        let desc = pull_cosign_referrer(ubi_registry, ubi_repo, tag, suffix, &ubi_desc, &ocidir)
            .await
            .with_context(|| format!("pulling cosign referrer '{tag}'"))?;
        println!("  Stored {suffix} artifact: {} -> {}", desc.digest(), tag);
        cosign_referrer_count += 1;
    }
    assert!(
        cosign_referrer_count >= 1,
        "should have stored at least 1 cosign referrer"
    );

    // Verify the cosign referrers are discoverable via find_referrers
    let ubi_referrers = ocidir.find_referrers(ubi_desc.digest(), None)?;
    assert_eq!(
        ubi_referrers.len(),
        cosign_referrer_count,
        "should find all stored cosign referrers"
    );
    println!(
        "  find_referrers returned {} referrer(s) for UBI image",
        ubi_referrers.len()
    );

    // Verify we can filter by cosign signature type
    let cosign_sig_type =
        MediaType::Other("application/vnd.dev.cosign.simplesigning.v1+json".into());
    let sig_refs = ocidir.find_referrers(ubi_desc.digest(), Some(&cosign_sig_type))?;
    assert!(
        !sig_refs.is_empty(),
        "should find cosign signature referrers"
    );
    println!("  Cosign signature referrers: {}", sig_refs.len());

    // Step 7: Pull bitnami/nginx and fetch its Notation signature via
    // the native OCI Referrers API (Docker Hub supports this natively)
    println!("--- Step 7: Fetch bitnami/nginx Notation referrers ---");
    let bitnami_repo = "bitnami/nginx";
    let bitnami_ref = format!("docker.io/{bitnami_repo}:latest");
    let bitnami_desc = pull_image(&bitnami_ref, &ocidir).await?;
    println!("  bitnami/nginx image: {}", bitnami_desc.digest());

    // The image manifest we pulled is the platform-specific one, but
    // the Notation signature is attached to the manifest *list* (index).
    // Fetch the manifest list digest.
    let client = new_registry_client();
    let bitnami_parsed: Reference = bitnami_ref.parse()?;
    let index_digest = client
        .fetch_manifest_digest(&bitnami_parsed, &RegistryAuth::Anonymous)
        .await
        .context("fetching bitnami manifest list digest")?;
    println!("  Manifest list digest: {index_digest}");

    // Query the native OCI Referrers API
    let referrer_descs = query_dockerhub_referrers(bitnami_repo, &index_digest).await?;
    println!(
        "  Referrers API returned {} referrer(s)",
        referrer_descs.len()
    );
    assert!(
        !referrer_descs.is_empty(),
        "bitnami/nginx should have at least one Notation signature referrer"
    );

    // Pull each referrer and store as an OCI artifact referencing our
    // local image manifest
    for rd in &referrer_descs {
        let at = rd.artifact_type.as_deref().unwrap_or(&rd.media_type);
        let desc = pull_referrer_artifact(bitnami_repo, rd, &bitnami_desc, &ocidir)
            .await
            .with_context(|| format!("pulling referrer {}", rd.digest))?;
        println!("  Stored referrer artifact: {} (type: {at})", desc.digest());
    }

    // Verify the Notation signature is discoverable
    let notation_type = MediaType::Other("application/vnd.cncf.notary.signature".into());
    let notation_refs = ocidir.find_referrers(bitnami_desc.digest(), Some(&notation_type))?;
    println!("  Notation signature referrers: {}", notation_refs.len());
    assert!(
        !notation_refs.is_empty(),
        "should find Notation signature referrer for bitnami/nginx"
    );

    // Step 8: Run fsck
    println!("--- Step 8: Run fsck ---");
    let validated = ocidir.fsck()?;
    println!("  fsck validated {validated} blob(s)");
    assert!(validated >= 4, "fsck should validate at least 4 blobs");

    // Step 9: Inspect
    println!("\n--- Step 9: Inspect ---");
    inspect(&ocidir)?;

    println!("\n=== Self-test passed ===");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init { path } => {
            ensure_ocidir(&path)?;
            println!("Initialised OCI directory at {path}");
        }
        Command::Pull {
            image,
            path,
            transport,
            tag,
        } => match transport {
            Transport::Registry => {
                if tag.is_some() {
                    eprintln!("warning: --tag is ignored with --transport=registry");
                }
                let ocidir = ensure_ocidir(&path)?;
                pull_image(&image, &ocidir).await?;
            }
            Transport::Oci => {
                let dest = ensure_ocidir(&path)?;
                pull_from_ocidir(&image, tag.as_deref(), &dest)?;
            }
        },
        Command::Push {
            path,
            image,
            transport,
            tag,
        } => match transport {
            Transport::Registry => {
                if tag.is_some() {
                    eprintln!("warning: --tag is ignored with --transport=registry");
                }
                let ocidir = open_ocidir(&path)?;
                push_image(&ocidir, &image).await?;
            }
            Transport::Oci => {
                let src = open_ocidir(&path)?;
                push_to_ocidir(&src, &image, tag.as_deref())?;
            }
        },
        Command::Inspect { path } => {
            let ocidir = open_ocidir(&path)?;
            inspect(&ocidir)?;
        }
        Command::Selftest => {
            selftest().await?;
        }
    }

    Ok(())
}
