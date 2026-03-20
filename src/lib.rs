#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use canon_json::CanonicalFormatter;
use cap_std::fs::{Dir, DirBuilderExt};
use cap_std_ext::cap_tempfile;
use cap_std_ext::dirext::CapStdExtDirExt;
use flate2::write::GzEncoder;
use oci_image::MediaType;
use oci_spec::image::{
    self as oci_image, Descriptor, Digest, ImageConfiguration, ImageIndex, ImageManifest, Platform,
    Sha256Digest,
};
use openssl::hash::{Hasher, MessageDigest};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, BufWriter, prelude::*};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;

// Re-export our dependencies that are used as part of the public API.
pub use cap_std_ext::cap_std;
pub use oci_spec;

/// Path inside an OCI directory to the blobs
const BLOBDIR: &str = "blobs/sha256";

const OCI_TAG_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// By default, an 8K buffer is used which is not optimal in general for larger
/// files, which blobs usually are. See also coreutils which uses a 128K buffer:
/// https://github.com/coreutils/coreutils/blob/6a3d2883/src/ioblksize.h -- and
/// Rust discussions in https://github.com/rust-lang/rust/issues/49921.
const BLOB_BUF_SIZE: usize = 128 * 1024;

/// Errors returned by this crate.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("i/o error")]
    /// An input/output error
    Io(#[from] std::io::Error),
    #[error("serialization error")]
    /// Returned when serialization or deserialization fails
    SerDe(#[from] serde_json::Error),
    #[error("parsing OCI value")]
    /// Returned when an OCI spec error occurs
    OciSpecError(#[from] oci_spec::OciSpecError),
    #[error("unexpected cryptographic routine error")]
    /// Returned when a cryptographic routine encounters an unexpected problem
    CryptographicError(Box<str>),
    #[error("Expected digest {expected} but found {found}")]
    /// Returned when a digest does not match
    DigestMismatch {
        /// Expected digest value
        expected: Box<str>,
        /// Found digest value
        found: Box<str>,
    },
    #[error("Expected size {expected} but found {found}")]
    /// Returned when a descriptor digest does not match what was expected
    SizeMismatch {
        /// Expected size value
        expected: u64,
        /// Found size value
        found: u64,
    },
    #[error("Expected digest algorithm sha256 but found {found}")]
    /// Returned when a digest algorithm is not supported
    UnsupportedDigestAlgorithm {
        /// The unsupported digest algorithm that was found
        found: Box<str>,
    },
    #[error("Cannot find the Image Index (index.json)")]
    /// Returned when the OCI Image Index (index.json) is missing
    MissingImageIndex,
    #[error("Image index contains no manifests")]
    /// Returned when the image index is empty
    EmptyImageIndex,
    #[error("Tag '{tag}' not found in image index")]
    /// Returned when a requested tag is not found
    TagNotFound {
        /// The tag that was not found
        tag: Box<str>,
    },
    #[error("No manifest found for platform {os}/{architecture}; available: {available}")]
    /// Returned when no manifest matches the requested platform
    NoMatchingPlatform {
        /// The requested OS
        os: Box<str>,
        /// The requested architecture
        architecture: Box<str>,
        /// Available platforms as a comma-separated list
        available: Box<str>,
    },
    #[error("Unexpected media type {media_type}")]
    /// Returned when there's an unexpected media type
    UnexpectedMediaType {
        /// The unexpected media type that was encountered
        media_type: MediaType,
    },
    #[error("Nested image indices are not supported")]
    /// Returned when a nested image index is encountered
    NestedImageIndex,
    #[error("error")]
    /// An unknown other error
    Other(Box<str>),
}

/// The error type returned from this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl From<openssl::error::Error> for Error {
    fn from(value: openssl::error::Error) -> Self {
        Self::CryptographicError(value.to_string().into())
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(value: openssl::error::ErrorStack) -> Self {
        Self::CryptographicError(value.to_string().into())
    }
}

// This is intentionally an empty struct
// See https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor
#[derive(Serialize, Deserialize)]
struct EmptyDescriptor {}

/// Completed blob metadata
#[derive(Debug)]
pub struct Blob {
    /// SHA-256 digest
    sha256: oci_image::Sha256Digest,
    /// Size
    size: u64,
}

impl Blob {
    /// The SHA-256 digest for this blob
    pub fn sha256(&self) -> &oci_image::Sha256Digest {
        &self.sha256
    }

    /// Descriptor
    pub fn descriptor(&self) -> oci_image::DescriptorBuilder {
        oci_image::DescriptorBuilder::default()
            .digest(self.sha256.clone())
            .size(self.size)
    }

    /// Return the size of this blob
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Result of resolving a manifest for a specific platform.
///
/// Contains the resolved manifest along with its descriptor, and optionally
/// the image index (manifest list) it was resolved from with its descriptor.
#[derive(Debug)]
pub struct ResolvedManifest {
    /// The resolved image manifest
    pub manifest: ImageManifest,
    /// The descriptor of the manifest (includes digest, size, media type)
    pub manifest_descriptor: Descriptor,
    /// The image index this manifest was resolved from, if any (with its descriptor)
    pub source_index: Option<(ImageIndex, Descriptor)>,
}

/// Completed layer metadata
#[derive(Debug)]
pub struct Layer {
    /// The underlying blob (usually compressed)
    pub blob: Blob,
    /// The uncompressed digest, which will be used for "diffid"s
    pub uncompressed_sha256: Sha256Digest,
    /// The media type of the layer
    pub media_type: MediaType,
}

impl Layer {
    /// Return the descriptor for this layer
    pub fn descriptor(&self) -> oci_image::DescriptorBuilder {
        self.blob.descriptor().media_type(self.media_type.clone())
    }

    /// Return a Digest instance for the uncompressed SHA-256.
    pub fn uncompressed_sha256_as_digest(&self) -> Digest {
        self.uncompressed_sha256.clone().into()
    }
}

/// Create an OCI blob.
pub struct BlobWriter<'a> {
    /// Compute checksum
    hash: Hasher,
    /// Target file
    target: Option<BufWriter<cap_tempfile::TempFile<'a>>>,
    size: u64,
}

impl Debug for BlobWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlobWriter")
            .field("target", &self.target)
            .field("size", &self.size)
            .finish()
    }
}

#[derive(Debug)]
/// An opened OCI directory.
pub struct OciDir {
    /// The underlying directory.
    dir: Dir,
    blobs_dir: Dir,
}

fn sha256_of_descriptor(desc: &Descriptor) -> Result<&str> {
    desc.as_digest_sha256()
        .ok_or_else(|| Error::UnsupportedDigestAlgorithm {
            found: desc.digest().to_string().into(),
        })
}

impl OciDir {
    /// Create an empty config descriptor.
    /// See https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor
    /// Our API right now always mutates a manifest, which means we need
    /// a "valid" manifest, which requires a "valid" config descriptor.
    fn empty_config_descriptor(&self) -> Result<oci_image::Descriptor> {
        let empty_descriptor = oci_image::DescriptorBuilder::default()
            .media_type(MediaType::EmptyJSON)
            .size(2_u32)
            .digest(Sha256Digest::from_str(
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            )?)
            .data("e30=")
            .build()?;

        if !self
            .dir
            .exists(OciDir::parse_descriptor_to_path(&empty_descriptor)?)
        {
            let mut blob = self.create_blob()?;
            serde_json::to_writer(&mut blob, &EmptyDescriptor {})?;
            blob.complete_verified_as(&empty_descriptor)?;
        }

        Ok(empty_descriptor)
    }

    /// Generate a valid empty manifest.  See above.
    pub fn new_empty_manifest(&self) -> Result<oci_image::ImageManifestBuilder> {
        Ok(oci_image::ImageManifestBuilder::default()
            .schema_version(oci_image::SCHEMA_VERSION)
            .config(self.empty_config_descriptor()?)
            .layers(Vec::new()))
    }

    /// Open the OCI directory at the target path; if it does not already
    /// have the standard OCI metadata, it is created.
    pub fn ensure(dir: Dir) -> Result<Self> {
        let mut db = cap_std::fs::DirBuilder::new();
        db.recursive(true).mode(0o755);
        dir.ensure_dir_with(BLOBDIR, &db)?;
        if !dir.try_exists("oci-layout")? {
            dir.atomic_write("oci-layout", r#"{"imageLayoutVersion":"1.0.0"}"#)?;
        }
        Self::open(dir)
    }

    /// Clone an OCI directory, using reflinks for blobs.
    pub fn clone_to(&self, destdir: &Dir, p: impl AsRef<Path>) -> Result<Self> {
        let p = p.as_ref();
        destdir.create_dir(p)?;
        let cloned = Self::ensure(destdir.open_dir(p)?)?;
        for blob in self.blobs_dir.entries()? {
            let blob = blob?;
            let path = Path::new(BLOBDIR).join(blob.file_name());
            let mut src = self.dir.open(&path).map(BufReader::new)?;
            self.dir
                .atomic_replace_with(&path, |w| std::io::copy(&mut src, w))?;
        }
        Ok(cloned)
    }

    /// Open an existing OCI directory.
    pub fn open(dir: Dir) -> Result<Self> {
        let blobs_dir = dir.open_dir(BLOBDIR)?;
        Self::open_with_external_blobs(dir, blobs_dir)
    }

    /// Open an existing OCI directory with a separate cap_std::Dir for blobs/sha256
    /// This is useful when `blobs/sha256` might contain symlinks pointing outside the oci
    /// directory, e.g. when sharing blobs across OCI repositories. The LXC OCI template uses this
    /// feature.
    pub fn open_with_external_blobs(dir: Dir, blobs_dir: Dir) -> Result<Self> {
        Ok(Self { dir, blobs_dir })
    }

    /// Return the underlying directory.
    pub fn dir(&self) -> &Dir {
        &self.dir
    }

    /// Return the underlying directory for blobs.
    pub fn blobs_dir(&self) -> &Dir {
        &self.blobs_dir
    }

    /// Write a serializable data (JSON) as an OCI blob
    pub fn write_json_blob<S: serde::Serialize>(
        &self,
        v: &S,
        media_type: oci_image::MediaType,
    ) -> Result<oci_image::DescriptorBuilder> {
        let mut w = BlobWriter::new(&self.dir)?;
        let mut ser = serde_json::Serializer::with_formatter(&mut w, CanonicalFormatter::new());
        v.serialize(&mut ser)?;
        let blob = w.complete()?;
        Ok(blob.descriptor().media_type(media_type))
    }

    /// Create a blob (can be anything).
    pub fn create_blob(&self) -> Result<BlobWriter<'_>> {
        BlobWriter::new(&self.dir)
    }

    /// Create a layer writer with a custom encoder and
    /// media type
    pub fn create_custom_layer<'a, W: WriteComplete<BlobWriter<'a>>>(
        &'a self,
        create: impl FnOnce(BlobWriter<'a>) -> std::io::Result<W>,
        media_type: MediaType,
    ) -> Result<LayerWriter<'a, W>> {
        let bw = BlobWriter::new(&self.dir)?;
        Ok(LayerWriter::new(create(bw)?, media_type))
    }

    /// Create a writer for a new uncompressed layer.
    ///
    /// This skips computing a separate uncompressed digest (diffid) since the
    /// blob content is identical to the uncompressed content.
    pub fn create_uncompressed_layer(&self) -> Result<LayerWriter<'_, BlobWriter<'_>>> {
        let bw = BlobWriter::new(&self.dir)?;
        Ok(LayerWriter::new_uncompressed(bw, MediaType::ImageLayer))
    }

    /// Create a writer for a new gzip+tar blob; the contents
    /// are not parsed, but are expected to be a tarball.
    pub fn create_gzip_layer<'a>(
        &'a self,
        c: Option<flate2::Compression>,
    ) -> Result<LayerWriter<'a, GzEncoder<BlobWriter<'a>>>> {
        let creator = |bw: BlobWriter<'a>| Ok(GzEncoder::new(bw, c.unwrap_or_default()));
        self.create_custom_layer(creator, MediaType::ImageLayerGzip)
    }

    /// Create a tar output stream, backed by a blob
    pub fn create_layer(
        &'_ self,
        c: Option<flate2::Compression>,
    ) -> Result<tar::Builder<LayerWriter<'_, GzEncoder<BlobWriter<'_>>>>> {
        Ok(tar::Builder::new(self.create_gzip_layer(c)?))
    }

    #[cfg(feature = "zstd")]
    /// Create a writer for a new zstd+tar blob; the contents
    /// are not parsed, but are expected to be a tarball.
    ///
    /// This method is only available when the `zstd` feature is enabled.
    pub fn create_layer_zstd<'a>(
        &'a self,
        compression_level: Option<i32>,
    ) -> Result<LayerWriter<'a, zstd::Encoder<'static, BlobWriter<'a>>>> {
        let creator = |bw: BlobWriter<'a>| zstd::Encoder::new(bw, compression_level.unwrap_or(0));
        self.create_custom_layer(creator, MediaType::ImageLayerZstd)
    }

    #[cfg(feature = "zstdmt")]
    /// Create a writer for a new zstd+tar blob; the contents
    /// are not parsed, but are expected to be a tarball.
    /// The compression is multithreaded.
    ///
    /// The `n_workers` parameter specifies the number of threads to use for compression, per
    /// [zstd::Encoder::multithread]]
    ///
    /// This method is only available when the `zstdmt` feature is enabled.
    pub fn create_layer_zstd_multithread<'a>(
        &'a self,
        compression_level: Option<i32>,
        n_workers: u32,
    ) -> Result<LayerWriter<'a, zstd::Encoder<'static, BlobWriter<'a>>>> {
        let creator = |bw: BlobWriter<'a>| {
            let mut encoder = zstd::Encoder::new(bw, compression_level.unwrap_or(0))?;
            encoder.multithread(n_workers)?;
            Ok(encoder)
        };
        self.create_custom_layer(creator, MediaType::ImageLayerZstd)
    }

    /// Add a layer to the top of the image stack.  The firsh pushed layer becomes the root.
    pub fn push_layer(
        &self,
        manifest: &mut oci_image::ImageManifest,
        config: &mut oci_image::ImageConfiguration,
        layer: Layer,
        description: &str,
        annotations: Option<HashMap<String, String>>,
    ) {
        self.push_layer_annotated(manifest, config, layer, annotations, description);
    }

    /// Add a layer to the top of the image stack with optional annotations.
    ///
    /// This is otherwise equivalent to [`Self::push_layer`].
    pub fn push_layer_annotated(
        &self,
        manifest: &mut oci_image::ImageManifest,
        config: &mut oci_image::ImageConfiguration,
        layer: Layer,
        annotations: Option<impl Into<HashMap<String, String>>>,
        description: &str,
    ) {
        let created = chrono::offset::Utc::now();
        self.push_layer_full(manifest, config, layer, annotations, description, created)
    }

    /// Add a layer to the top of the image stack with optional annotations and desired timestamp.
    ///
    /// This is otherwise equivalent to [`Self::push_layer_annotated`].
    pub fn push_layer_full(
        &self,
        manifest: &mut oci_image::ImageManifest,
        config: &mut oci_image::ImageConfiguration,
        layer: Layer,
        annotations: Option<impl Into<HashMap<String, String>>>,
        description: &str,
        created: chrono::DateTime<chrono::Utc>,
    ) {
        let history = oci_image::HistoryBuilder::default()
            .created(created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .created_by(description.to_string())
            .build()
            .unwrap();
        self.push_layer_with_history_annotated(manifest, config, layer, annotations, Some(history));
    }

    /// Add a layer to the top of the image stack with optional annotations and desired history entry.
    ///
    /// This is otherwise equivalent to [`Self::push_layer_annotated`].
    pub fn push_layer_with_history_annotated(
        &self,
        manifest: &mut oci_image::ImageManifest,
        config: &mut oci_image::ImageConfiguration,
        layer: Layer,
        annotations: Option<impl Into<HashMap<String, String>>>,
        history: Option<oci_image::History>,
    ) {
        let mut builder = layer.descriptor();
        if let Some(annotations) = annotations {
            builder = builder.annotations(annotations);
        }
        let blobdesc = builder.build().unwrap();
        manifest.layers_mut().push(blobdesc);
        let mut rootfs = config.rootfs().clone();
        rootfs
            .diff_ids_mut()
            .push(layer.uncompressed_sha256_as_digest().to_string());
        config.set_rootfs(rootfs);
        let history = if let Some(history) = history {
            history
        } else {
            oci_image::HistoryBuilder::default().build().unwrap()
        };
        config.history_mut().get_or_insert_default().push(history);
    }

    /// Add a layer to the top of the image stack with desired history entry.
    ///
    /// This is otherwise equivalent to [`Self::push_layer`].
    pub fn push_layer_with_history(
        &self,
        manifest: &mut oci_image::ImageManifest,
        config: &mut oci_image::ImageConfiguration,
        layer: Layer,
        history: Option<oci_image::History>,
    ) {
        let annotations: Option<HashMap<_, _>> = None;
        self.push_layer_with_history_annotated(manifest, config, layer, annotations, history);
    }

    fn parse_descriptor_to_path(desc: &oci_spec::image::Descriptor) -> Result<PathBuf> {
        let digest = sha256_of_descriptor(desc)?;
        Ok(PathBuf::from(digest))
    }

    /// Open a blob; its size is validated as a sanity check.
    pub fn read_blob(&self, desc: &oci_spec::image::Descriptor) -> Result<File> {
        let path = Self::parse_descriptor_to_path(desc)?;
        let f = self.blobs_dir.open(path).map(|f| f.into_std())?;
        let expected: u64 = desc.size();
        let found = f.metadata()?.len();
        if expected != found {
            return Err(Error::SizeMismatch { expected, found });
        }
        Ok(f)
    }

    /// Returns `true` if the blob with this digest is already present.
    pub fn has_blob(&self, desc: &oci_spec::image::Descriptor) -> Result<bool> {
        let path = Self::parse_descriptor_to_path(desc)?;
        self.blobs_dir.try_exists(path).map_err(Into::into)
    }

    /// Returns `true` if the manifest is already present.
    pub fn has_manifest(&self, desc: &oci_spec::image::Descriptor) -> Result<bool> {
        let index = self.read_index()?;
        Ok(index
            .manifests()
            .iter()
            .any(|m| m.digest() == desc.digest()))
    }

    /// Read a JSON blob.
    pub fn read_json_blob<T: serde::de::DeserializeOwned>(
        &self,
        desc: &oci_spec::image::Descriptor,
    ) -> Result<T> {
        let blob = BufReader::new(self.read_blob(desc)?);
        serde_json::from_reader(blob).map_err(Into::into)
    }

    /// Write a configuration blob.
    pub fn write_config(
        &self,
        config: oci_image::ImageConfiguration,
    ) -> Result<oci_image::Descriptor> {
        Ok(self
            .write_json_blob(&config, MediaType::ImageConfig)?
            .build()?)
    }

    /// Read the image index.
    pub fn read_index(&self) -> Result<ImageIndex> {
        let r = if let Some(index) = self.dir.open_optional("index.json")?.map(BufReader::new) {
            oci_image::ImageIndex::from_reader(index)?
        } else {
            return Err(Error::MissingImageIndex);
        };
        Ok(r)
    }

    /// Write a manifest as a blob, and replace the index with a reference to it.
    ///
    /// When the manifest has a `subject` field (i.e. it is a referrer artifact),
    /// the `artifact_type` and `annotations` from the manifest are automatically
    /// propagated to the descriptor in the index, as required by the OCI
    /// distribution spec's Referrers API.
    ///
    /// If the manifest has an explicit `artifact_type`, that value is used on the
    /// descriptor. Otherwise, if the manifest has a `subject`, the descriptor's
    /// `artifact_type` falls back to `config.mediaType` (per the spec).
    pub fn insert_manifest(
        &self,
        manifest: oci_image::ImageManifest,
        tag: Option<&str>,
        platform: oci_image::Platform,
    ) -> Result<Descriptor> {
        let mut desc_builder = self
            .write_json_blob(&manifest, MediaType::ImageManifest)?
            .platform(platform);

        // Per the OCI distribution spec, descriptors in the index for manifests
        // with a `subject` must carry `artifactType` and all annotations from
        // the manifest. This enables the Referrers API to work without fetching
        // each manifest blob.
        if manifest.subject().is_some() {
            let effective_artifact_type = manifest
                .artifact_type()
                .clone()
                .unwrap_or_else(|| manifest.config().media_type().clone());
            desc_builder = desc_builder.artifact_type(effective_artifact_type);

            // Copy manifest-level annotations to the descriptor
            if let Some(annos) = manifest.annotations() {
                desc_builder = desc_builder.annotations(annos.clone());
            }
        } else if let Some(at) = manifest.artifact_type() {
            // Even without a subject, propagate artifact_type if set
            desc_builder = desc_builder.artifact_type(at.clone());
        }

        let mut manifest_desc = desc_builder.build()?;
        if let Some(tag) = tag {
            let mut annotations = manifest_desc.annotations().clone().unwrap_or_default();
            annotations.insert(OCI_TAG_ANNOTATION.to_string(), tag.to_string());
            manifest_desc.set_annotations(Some(annotations));
        }

        self.append_to_index(manifest_desc.clone(), tag)?;
        Ok(manifest_desc)
    }

    /// Write an `ImageIndex` to `index.json` using canonical JSON formatting.
    fn write_index(&self, index: &oci_image::ImageIndex) -> Result<()> {
        self.dir
            .atomic_replace_with("index.json", |mut w| -> Result<()> {
                let mut ser =
                    serde_json::Serializer::with_formatter(&mut w, CanonicalFormatter::new());
                index.serialize(&mut ser)?;
                Ok(())
            })?;
        Ok(())
    }

    /// Convenience helper to write the provided config, update the manifest to use it, then call [`insert_manifest`].
    pub fn insert_manifest_and_config(
        &self,
        mut manifest: oci_image::ImageManifest,
        config: oci_image::ImageConfiguration,
        tag: Option<&str>,
        platform: oci_image::Platform,
    ) -> Result<Descriptor> {
        let config = self.write_config(config)?;
        manifest.set_config(config);
        self.insert_manifest(manifest, tag, platform)
    }

    /// Create and insert an artifact manifest that references another manifest
    /// via the `subject` field.
    ///
    /// This creates an OCI artifact manifest with the given `artifact_type`,
    /// pointing to `subject` as the referenced manifest. The artifact's config
    /// is set to the [empty descriptor][empty] and layers contain the provided
    /// content blobs (or a single empty descriptor if no layers are provided).
    ///
    /// Per the [OCI image spec][artifact-usage], when `config.mediaType` is set
    /// to the empty value, `artifact_type` MUST be defined.
    ///
    /// The resulting descriptor in the index carries `artifact_type` and all
    /// manifest annotations, enabling the [Referrers API][referrers] to list
    /// this artifact without fetching the manifest blob.
    ///
    /// Unlike [`insert_manifest`](Self::insert_manifest), the descriptor in
    /// the index does not carry a `platform` field, since artifacts are not
    /// platform-specific.
    ///
    /// [empty]: https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidance-for-an-empty-descriptor
    /// [artifact-usage]: https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidelines-for-artifact-usage
    /// [referrers]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers
    pub fn insert_artifact_manifest(
        &self,
        subject: Descriptor,
        artifact_type: MediaType,
        layers: Vec<Descriptor>,
        annotations: Option<HashMap<String, String>>,
    ) -> Result<Descriptor> {
        let empty_descriptor = self.empty_config_descriptor()?;

        // Per the spec, if no layers are provided, use a single empty
        // descriptor as a placeholder layer.
        let layers = if layers.is_empty() {
            vec![empty_descriptor.clone()]
        } else {
            layers
        };

        let mut manifest_builder = oci_image::ImageManifestBuilder::default()
            .schema_version(oci_image::SCHEMA_VERSION)
            .config(empty_descriptor)
            .layers(layers)
            .artifact_type(artifact_type.clone())
            .subject(subject);

        if let Some(annos) = annotations {
            manifest_builder = manifest_builder.annotations(annos);
        }

        let manifest = manifest_builder.build()?;

        // Write the manifest blob and build a descriptor without a platform
        // field. We propagate artifact_type and annotations to the descriptor
        // for the Referrers API, as required by the OCI distribution spec.
        let mut desc_builder = self
            .write_json_blob(&manifest, MediaType::ImageManifest)?
            .artifact_type(artifact_type);

        if let Some(annos) = manifest.annotations() {
            desc_builder = desc_builder.annotations(annos.clone());
        }

        let manifest_desc = desc_builder.build()?;
        self.append_to_index(manifest_desc.clone(), None)?;
        Ok(manifest_desc)
    }

    /// Append a descriptor to the index, optionally replacing any existing
    /// entry with the same tag.
    fn append_to_index(&self, desc: Descriptor, tag: Option<&str>) -> Result<()> {
        let index = match self.read_index() {
            Ok(mut index) => {
                let mut manifests = index.manifests().clone();
                if let Some(tag) = tag {
                    manifests.retain(|d| !Self::descriptor_is_tagged(d, tag));
                }
                manifests.push(desc);
                index.set_manifests(manifests);
                index
            }
            Err(Error::MissingImageIndex) => oci_image::ImageIndexBuilder::default()
                .schema_version(oci_image::SCHEMA_VERSION)
                .manifests(vec![desc])
                .build()?,
            Err(e) => return Err(e),
        };
        self.write_index(&index)
    }

    /// Find all descriptors in the index that reference the given subject
    /// digest, as required by the [Referrers API][referrers].
    ///
    /// Returns descriptors from the index whose corresponding manifest has a
    /// `subject` field matching the given digest. The returned descriptors
    /// include `artifact_type` and annotations as required by the spec.
    ///
    /// The `artifact_type_filter` parameter optionally filters results to only
    /// include referrers with a matching `artifact_type`.
    ///
    /// Note: this reads each manifest blob from disk to inspect its `subject`
    /// field, so the cost scales with the number of manifests in the index.
    ///
    /// [referrers]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers
    pub fn find_referrers(
        &self,
        subject_digest: &Digest,
        artifact_type_filter: Option<&MediaType>,
    ) -> Result<Vec<Descriptor>> {
        let index = self.read_index()?;
        let mut referrers = Vec::new();

        for desc in index.manifests() {
            // Only image manifests can carry a subject field; skip image
            // indices and other media types to avoid deserialization errors.
            if desc.media_type() != &MediaType::ImageManifest {
                continue;
            }

            let manifest: ImageManifest = self.read_json_blob(desc)?;

            let subject = match manifest.subject() {
                Some(s) => s,
                None => continue,
            };

            if subject.digest() != subject_digest {
                continue;
            }

            // Apply artifact_type filter if requested
            if let Some(filter) = artifact_type_filter {
                let effective_type = manifest
                    .artifact_type()
                    .as_ref()
                    .unwrap_or(manifest.config().media_type());
                if effective_type != filter {
                    continue;
                }
            }

            referrers.push(desc.clone());
        }

        Ok(referrers)
    }

    /// Write a manifest as a blob, and replace the index with a reference to it.
    pub fn replace_with_single_manifest(
        &self,
        manifest: oci_image::ImageManifest,
        platform: oci_image::Platform,
    ) -> Result<()> {
        let manifest = self
            .write_json_blob(&manifest, MediaType::ImageManifest)?
            .platform(platform)
            .build()
            .unwrap();

        let index_data = oci_image::ImageIndexBuilder::default()
            .schema_version(oci_image::SCHEMA_VERSION)
            .manifests(vec![manifest])
            .build()
            .unwrap();
        self.write_index(&index_data)
    }

    fn descriptor_is_tagged(d: &Descriptor, tag: &str) -> bool {
        d.annotations()
            .as_ref()
            .and_then(|annos| annos.get(OCI_TAG_ANNOTATION))
            .filter(|tagval| tagval.as_str() == tag)
            .is_some()
    }

    /// Find the manifest with the provided tag
    pub fn find_manifest_with_tag(&self, tag: &str) -> Result<Option<oci_image::ImageManifest>> {
        let desc = self.find_manifest_descriptor_with_tag(tag)?;
        desc.map(|img| self.read_json_blob(&img)).transpose()
    }

    /// Find the manifest descriptor with the provided tag
    pub fn find_manifest_descriptor_with_tag(
        &self,
        tag: &str,
    ) -> Result<Option<oci_image::Descriptor>> {
        let idx = self.read_index()?;
        Ok(idx
            .manifests()
            .iter()
            .find(|desc| Self::descriptor_is_tagged(desc, tag))
            .cloned())
    }

    /// Open an image manifest for the current platform.
    ///
    /// This resolves the appropriate manifest from the index for the native
    /// platform (OS and architecture). If `tag` is provided, only manifests
    /// with that tag annotation are considered.
    ///
    /// If the index contains an image index (manifest list), it is "peeled"
    /// to get the underlying manifests. Nested image indices are not supported.
    ///
    /// Returns a [`ResolvedManifest`] containing the manifest, its digest,
    /// and optionally the image index it was resolved from with its digest.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The index cannot be read
    /// - The index is empty
    /// - A tag is specified but not found
    /// - No manifest matches the native platform
    /// - A nested image index is encountered
    pub fn open_image_this_platform(&self, tag: Option<&str>) -> Result<ResolvedManifest> {
        let index = self.read_index()?;
        let manifests = index.manifests();

        // Filter by tag if specified, returning early on empty results
        let candidates: Vec<_> = if let Some(tag) = tag {
            let tagged: Vec<_> = manifests
                .iter()
                .filter(|d| Self::descriptor_is_tagged(d, tag))
                .collect();
            if tagged.is_empty() {
                return Err(Error::TagNotFound { tag: tag.into() });
            }
            tagged
        } else {
            if manifests.is_empty() {
                return Err(Error::EmptyImageIndex);
            }
            manifests.iter().collect()
        };

        // Get the native platform
        let native_platform = Platform::default();

        // Collect all found candidate descriptors for error reporting
        let mut found_candidates: Vec<Descriptor> = Vec::new();

        for desc in candidates {
            match desc.media_type() {
                MediaType::ImageManifest => {
                    // Direct manifest in the top-level index
                    if let Some(platform) = desc.platform().as_ref()
                        && Self::platform_compatible(platform, &native_platform)
                    {
                        let manifest = self.read_json_blob::<ImageManifest>(desc)?;
                        return Ok(ResolvedManifest {
                            manifest,
                            manifest_descriptor: desc.clone(),
                            source_index: None,
                        });
                    }
                    found_candidates.push(desc.clone());
                }
                MediaType::ImageIndex => {
                    // Peel the manifest list
                    let nested: ImageIndex = self.read_json_blob(desc)?;
                    let index_descriptor = desc.clone();

                    if let Some(resolved) = self.resolve_manifest_list(
                        nested,
                        index_descriptor,
                        &native_platform,
                        &mut found_candidates,
                    )? {
                        return Ok(resolved);
                    }
                }
                other => {
                    return Err(Error::UnexpectedMediaType {
                        media_type: other.clone(),
                    });
                }
            }
        }

        // No match found
        Err(Error::NoMatchingPlatform {
            os: native_platform.os().to_string().into(),
            architecture: native_platform.architecture().to_string().into(),
            available: Self::format_available_platforms(found_candidates.iter()),
        })
    }

    /// Resolve a manifest from an image index (manifest list) for a given platform.
    ///
    /// Iterates the manifests within the index, returning the first one that
    /// matches `native_platform`. Non-matching descriptors are appended to
    /// `found_candidates` so callers can include them in error messages.
    ///
    /// Returns `Ok(None)` if no manifest in this index matched.
    fn resolve_manifest_list(
        &self,
        index: ImageIndex,
        index_descriptor: Descriptor,
        native_platform: &Platform,
        found_candidates: &mut Vec<Descriptor>,
    ) -> Result<Option<ResolvedManifest>> {
        for desc in index.manifests() {
            match desc.media_type() {
                MediaType::ImageIndex => {
                    return Err(Error::NestedImageIndex);
                }
                MediaType::ImageManifest => {
                    if let Some(platform) = desc.platform().as_ref()
                        && Self::platform_compatible(platform, native_platform)
                    {
                        let manifest = self.read_json_blob::<ImageManifest>(desc)?;
                        return Ok(Some(ResolvedManifest {
                            manifest,
                            manifest_descriptor: desc.clone(),
                            source_index: Some((index, index_descriptor)),
                        }));
                    }
                    found_candidates.push(desc.clone());
                }
                other => {
                    return Err(Error::UnexpectedMediaType {
                        media_type: other.clone(),
                    });
                }
            }
        }
        Ok(None)
    }

    /// Format the available platforms from a list of descriptors for error messages.
    /// Limits output to 10 platforms to prevent excessive memory usage.
    fn format_available_platforms<'a>(manifests: impl Iterator<Item = &'a Descriptor>) -> Box<str> {
        const MAX_PLATFORMS_IN_ERROR: usize = 10;

        let platforms: Vec<_> = manifests
            .filter_map(|d| {
                d.platform()
                    .as_ref()
                    .map(|p| format!("{}/{}", p.os(), p.architecture()))
            })
            .take(MAX_PLATFORMS_IN_ERROR + 1) // Take one extra to detect truncation
            .collect();

        if platforms.is_empty() {
            return "(no platform info)".into();
        }

        if platforms.len() > MAX_PLATFORMS_IN_ERROR {
            let truncated: Vec<_> = platforms.into_iter().take(MAX_PLATFORMS_IN_ERROR).collect();
            format!("{}, ...", truncated.join(", ")).into()
        } else {
            platforms.join(", ").into()
        }
    }

    /// Check if a platform is compatible with the native platform.
    ///
    /// Platform has additional optional fields (variant, os_version,
    /// os_features, features) which are primarily used for Windows images.
    /// We only compare architecture and OS for compatibility.
    fn platform_compatible(platform: &Platform, native: &Platform) -> bool {
        platform.architecture() == native.architecture() && platform.os() == native.os()
    }

    /// Verify a blob's SHA-256 digest matches its descriptor.
    fn verify_blob_digest(&self, desc: &Descriptor) -> Result<()> {
        let expected = sha256_of_descriptor(desc)?;
        let mut f = self.read_blob(desc)?;
        let mut digest = Hasher::new(MessageDigest::sha256())?;
        std::io::copy(&mut f, &mut digest)?;
        let found = hex::encode(
            digest
                .finish()
                .map_err(|e| Error::Other(e.to_string().into()))?,
        );
        if expected != found {
            return Err(Error::DigestMismatch {
                expected: expected.into(),
                found: found.into(),
            });
        }
        Ok(())
    }

    /// Verify a single manifest and all of its referenced objects.
    /// Skips already validated blobs referenced by digest in `validated`,
    /// and updates that set with ones we did validate.
    fn fsck_one_manifest(
        &self,
        manifest: &ImageManifest,
        validated: &mut HashSet<Box<str>>,
    ) -> Result<()> {
        let config_digest = sha256_of_descriptor(manifest.config())?;
        // Always verify the config blob digest, regardless of media type.
        self.verify_blob_digest(manifest.config())?;
        // Additionally validate the content structure for known types.
        match manifest.config().media_type() {
            MediaType::ImageConfig => {
                let _: ImageConfiguration = self.read_json_blob(manifest.config())?;
            }
            MediaType::EmptyJSON => {
                let _: EmptyDescriptor = self.read_json_blob(manifest.config())?;
            }
            // Per the OCI image spec, implementations MUST NOT error on
            // encountering an unknown config mediaType.
            _ => {}
        }
        validated.insert(config_digest.into());
        for layer in manifest.layers() {
            let expected = sha256_of_descriptor(layer)?;
            if validated.contains(expected) {
                continue;
            }
            self.verify_blob_digest(layer)?;
            validated.insert(expected.into());
        }
        Ok(())
    }

    /// Verify consistency of the index, its manifests, the config and blobs (all the latter)
    /// by verifying their descriptor.
    pub fn fsck(&self) -> Result<u64> {
        let index = self.read_index()?;
        let mut validated_blobs = HashSet::new();
        for manifest_descriptor in index.manifests() {
            let expected_sha256 = sha256_of_descriptor(manifest_descriptor)?;
            let manifest: ImageManifest = self.read_json_blob(manifest_descriptor)?;
            validated_blobs.insert(expected_sha256.into());
            self.fsck_one_manifest(&manifest, &mut validated_blobs)?;
        }
        Ok(validated_blobs.len().try_into().unwrap())
    }
}

impl<'a> BlobWriter<'a> {
    fn new(ocidir: &'a Dir) -> Result<Self> {
        Ok(Self {
            hash: Hasher::new(MessageDigest::sha256())?,
            // FIXME add ability to choose filename after completion
            target: Some(BufWriter::with_capacity(
                BLOB_BUF_SIZE,
                cap_tempfile::TempFile::new(ocidir)?,
            )),
            size: 0,
        })
    }

    /// Finish writing this blob, verifying its digest and size against the expected descriptor.
    pub fn complete_verified_as(mut self, descriptor: &Descriptor) -> Result<Blob> {
        let expected_digest = sha256_of_descriptor(descriptor)?;
        let found_digest = hex::encode(self.hash.finish()?);
        if found_digest.as_str() != expected_digest {
            return Err(Error::DigestMismatch {
                expected: expected_digest.into(),
                found: found_digest.into(),
            });
        }
        let descriptor_size: u64 = descriptor.size();
        if self.size != descriptor_size {
            return Err(Error::SizeMismatch {
                expected: descriptor_size,
                found: self.size,
            });
        }
        self.complete_as(&found_digest)
    }

    /// Finish writing this blob object with the supplied name
    fn complete_as(mut self, sha256_digest: &str) -> Result<Blob> {
        let destname = &format!("{}/{}", BLOBDIR, sha256_digest);
        let target = self.target.take().unwrap();
        target.into_inner().unwrap().replace(destname)?;
        Ok(Blob {
            sha256: Sha256Digest::from_str(sha256_digest).unwrap(),
            size: self.size,
        })
    }

    /// Finish writing this blob object.
    pub fn complete(mut self) -> Result<Blob> {
        let sha256 = hex::encode(self.hash.finish()?);
        self.complete_as(&sha256)
    }
}

impl std::io::Write for BlobWriter<'_> {
    fn write(&mut self, srcbuf: &[u8]) -> std::io::Result<usize> {
        let written = self.target.as_mut().unwrap().write(srcbuf)?;
        self.hash.update(&srcbuf[..written])?;
        self.size += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer that can be finalized to return an inner writer.
pub trait WriteComplete<W>: Write {
    /// Complete the write operation and return the inner writer
    fn complete(self) -> std::io::Result<W>;
}

impl<W> WriteComplete<W> for GzEncoder<W>
where
    W: Write,
{
    fn complete(self) -> std::io::Result<W> {
        self.finish()
    }
}

// This is used in the uncompressed path.
impl<'a> WriteComplete<BlobWriter<'a>> for BlobWriter<'a> {
    fn complete(self) -> std::io::Result<Self> {
        Ok(self)
    }
}

#[cfg(feature = "zstd")]
impl<W> WriteComplete<W> for zstd::Encoder<'_, W>
where
    W: Write,
{
    fn complete(self) -> std::io::Result<W> {
        self.finish()
    }
}

/// A writer for a layer.
pub struct LayerWriter<'a, W>
where
    W: WriteComplete<BlobWriter<'a>>,
{
    inner: Sha256Writer<W>,
    media_type: MediaType,
    marker: PhantomData<&'a ()>,
}

impl<'a, W> std::fmt::Debug for LayerWriter<'a, W>
where
    W: WriteComplete<BlobWriter<'a>>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayerWriter")
            .field("media_type", &self.media_type)
            .finish_non_exhaustive()
    }
}

impl<'a, W> LayerWriter<'a, W>
where
    W: WriteComplete<BlobWriter<'a>>,
{
    /// Create a new LayerWriter with the given inner writer and media type.
    ///
    /// This computes a separate SHA-256 digest of the uncompressed data
    /// (the "diffid") inline as data is written.
    pub fn new(inner: W, media_type: oci_image::MediaType) -> Self {
        Self {
            inner: Sha256Writer::new(inner),
            media_type,
            marker: PhantomData,
        }
    }

    /// Create a new LayerWriter that skips computing a separate uncompressed
    /// digest.
    ///
    /// The blob digest is used as the diffid. This is correct when the encoder
    /// does not transform the data (i.e. no compression), since the blob
    /// content is identical to the uncompressed content.
    pub fn new_uncompressed(inner: W, media_type: oci_image::MediaType) -> Self {
        Self {
            inner: Sha256Writer::new_passthrough(inner),
            media_type,
            marker: PhantomData,
        }
    }

    /// Complete the layer writing and return the layer descriptor.
    pub fn complete(self) -> Result<Layer> {
        let (uncompressed_sha256, enc) = self.inner.finish();
        let blob = enc.complete()?.complete()?;
        // NB: None here means that a separate uncompressed digest wasn't
        // calculated because the underlying blob writer is itself uncompressed.
        // So we can just reuse its calculated digest.
        let uncompressed_sha256 = uncompressed_sha256.unwrap_or_else(|| blob.sha256().clone());
        Ok(Layer {
            blob,
            uncompressed_sha256,
            media_type: self.media_type,
        })
    }
}

impl<'a, W> std::io::Write for LayerWriter<'a, W>
where
    W: WriteComplete<BlobWriter<'a>>,
{
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.inner.write(data)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Wraps a writer and optionally calculates the SHA-256 digest of data written
/// to the inner writer.
///
/// When created with [`Sha256Writer::new`], a SHA-256 digest is computed
/// inline. When created with [`Sha256Writer::new_passthrough`], no hashing is
/// performed and all writes pass through directly to the inner writer.
struct Sha256Writer<W> {
    inner: W,
    sha: Option<openssl::sha::Sha256>,
}

impl<W> Sha256Writer<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            sha: Some(openssl::sha::Sha256::new()),
        }
    }

    /// Create a passthrough writer that does not compute a digest. Embedding
    /// passthrough directly into this type avoids complicating the LayerWriter
    /// generics... this is a private API anyway.
    pub(crate) fn new_passthrough(inner: W) -> Self {
        Self { inner, sha: None }
    }

    /// Return the hex-encoded sha256 digest of the written data (if computed),
    /// and the underlying writer.
    pub(crate) fn finish(self) -> (Option<Sha256Digest>, W) {
        let digest = self.sha.map(|sha| {
            let hex = hex::encode(sha.finish());
            Sha256Digest::from_str(&hex).unwrap()
        });
        (digest, self.inner)
    }
}

impl<W> Write for Sha256Writer<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.inner.write(buf)?;
        if let Some(ref mut sha) = self.sha {
            sha.update(&buf[..len]);
        }
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use cap_std::fs::OpenOptions;
    use oci_spec::image::{Arch, HistoryBuilder, Os};

    use super::*;

    /// Create a new temporary OCI directory for testing.
    fn new_ocidir() -> Result<(cap_tempfile::TempDir, OciDir)> {
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let w = OciDir::ensure(td.try_clone()?)?;
        Ok((td, w))
    }

    /// Build an empty `ImageConfiguration` with all defaults.
    fn new_empty_config() -> oci_image::ImageConfiguration {
        oci_image::ImageConfigurationBuilder::default()
            .build()
            .unwrap()
    }

    /// Create a gzip layer with the given content bytes and return the completed layer.
    fn create_test_layer(w: &OciDir, content: &[u8]) -> Result<Layer> {
        let mut layerw = w.create_gzip_layer(None)?;
        layerw.write_all(content)?;
        layerw.complete()
    }

    /// Create a simple, valid single-manifest image in the OCI directory and return
    /// the manifest descriptor. The manifest has an empty config and no layers.
    fn insert_default_manifest(
        w: &OciDir,
        tag: Option<&str>,
    ) -> Result<(oci_image::ImageManifest, Descriptor)> {
        let manifest = w.new_empty_manifest()?.build()?;
        let config = new_empty_config();
        let desc = w.insert_manifest_and_config(
            manifest.clone(),
            config,
            tag,
            oci_image::Platform::default(),
        )?;
        Ok((manifest, desc))
    }

    const MANIFEST_DERIVE: &str = r#"{
        "schemaVersion": 2,
        "config": {
          "mediaType": "application/vnd.oci.image.config.v1+json",
          "digest": "sha256:54977ab597b345c2238ba28fe18aad751e5c59dc38b9393f6f349255f0daa7fc",
          "size": 754
        },
        "layers": [
          {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:ee02768e65e6fb2bb7058282338896282910f3560de3e0d6cd9b1d5985e8360d",
            "size": 5462
          },
          {
            "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            "digest": "sha256:d203cef7e598fa167cb9e8b703f9f20f746397eca49b51491da158d64968b429",
            "size": 214
          }
        ],
        "annotations": {
          "ostree.commit": "3cb6170b6945065c2475bc16d7bebcc84f96b4c677811a6751e479b89f8c3770",
          "ostree.version": "42.0"
        }
      }
    "#;

    #[test]
    fn manifest() -> Result<()> {
        let m: oci_image::ImageManifest = serde_json::from_str(MANIFEST_DERIVE)?;
        assert_eq!(
            m.layers()[0].digest().to_string(),
            "sha256:ee02768e65e6fb2bb7058282338896282910f3560de3e0d6cd9b1d5985e8360d"
        );
        Ok(())
    }

    #[test]
    fn test_build() -> Result<()> {
        let (_td, w) = new_ocidir()?;
        let root_layer = create_test_layer(&w, b"pretend this is a tarball")?;
        let root_layer_desc = root_layer.descriptor().build().unwrap();
        assert_eq!(
            root_layer.uncompressed_sha256.digest(),
            "349438e5faf763e8875b43de4d7101540ef4d865190336c2cc549a11f33f8d7c"
        );
        // Nothing referencing this blob yet
        assert!(matches!(w.fsck().unwrap_err(), Error::MissingImageIndex));
        assert!(w.has_blob(&root_layer_desc).unwrap());

        // Check that we don't find nonexistent blobs
        assert!(
            !w.has_blob(&Descriptor::new(
                MediaType::ImageLayerGzip,
                root_layer.blob.size,
                root_layer.uncompressed_sha256.clone()
            ))
            .unwrap()
        );

        let mut manifest = w.new_empty_manifest()?.build()?;
        let mut config = new_empty_config();
        let annotations: Option<HashMap<String, String>> = None;
        w.push_layer(&mut manifest, &mut config, root_layer, "root", annotations);
        {
            let history = config.history().as_ref().unwrap().first().unwrap();
            assert_eq!(history.created_by().as_ref().unwrap(), "root");
            let created = history.created().as_deref().unwrap();
            let ts = chrono::DateTime::parse_from_rfc3339(created)
                .unwrap()
                .to_utc();
            let now = chrono::offset::Utc::now();
            assert_eq!(now.years_since(ts).unwrap(), 0);
        }
        let config = w.write_config(config)?;
        manifest.set_config(config);
        w.replace_with_single_manifest(manifest.clone(), oci_image::Platform::default())?;
        assert_eq!(w.read_index().unwrap().manifests().len(), 1);
        assert_eq!(w.fsck().unwrap(), 3);
        // Also verify that corrupting a blob is found
        {
            let root_layer_sha256 = root_layer_desc.as_digest_sha256().unwrap();
            let mut f = w.dir.open_with(
                format!("blobs/sha256/{root_layer_sha256}"),
                OpenOptions::new().write(true),
            )?;
            let l = f.metadata()?.len();
            f.seek(std::io::SeekFrom::End(0))?;
            f.write_all(b"\0")?;
            assert!(w.fsck().is_err());
            f.set_len(l)?;
            assert_eq!(w.fsck().unwrap(), 3);
        }

        let idx = w.read_index()?;
        let manifest_desc = idx.manifests().first().unwrap();
        let read_manifest = w.read_json_blob(manifest_desc).unwrap();
        assert_eq!(&read_manifest, &manifest);

        let desc: Descriptor =
            w.insert_manifest(manifest, Some("latest"), oci_image::Platform::default())?;
        assert!(w.has_manifest(&desc).unwrap());
        // There's more than one now
        assert_eq!(w.read_index().unwrap().manifests().len(), 2);

        assert!(w.find_manifest_with_tag("noent").unwrap().is_none());
        let found_via_tag = w.find_manifest_with_tag("latest").unwrap().unwrap();
        assert_eq!(found_via_tag, read_manifest);

        let root_layer = create_test_layer(&w, b"pretend this is an updated tarball")?;
        let mut manifest = w.new_empty_manifest()?.build()?;
        let mut config = new_empty_config();
        w.push_layer(&mut manifest, &mut config, root_layer, "root", None);
        let _: Descriptor = w.insert_manifest_and_config(
            manifest,
            config,
            Some("latest"),
            oci_image::Platform::default(),
        )?;
        assert_eq!(w.read_index().unwrap().manifests().len(), 2);
        assert_eq!(w.fsck().unwrap(), 6);
        Ok(())
    }

    #[test]
    fn test_complete_verified_as() -> Result<()> {
        let (_td, oci_dir) = new_ocidir()?;

        // Test a successful write
        let empty_json_digest = oci_image::DescriptorBuilder::default()
            .media_type(MediaType::EmptyJSON)
            .size(2u32)
            .digest(Sha256Digest::from_str(
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            )?)
            .build()?;

        let mut empty_json_blob = oci_dir.create_blob()?;
        empty_json_blob.write_all(b"{}")?;
        let blob = empty_json_blob.complete_verified_as(&empty_json_digest)?;
        assert_eq!(blob.sha256().digest(), empty_json_digest.digest().digest());

        // And a checksum mismatch
        let test_descriptor = oci_image::DescriptorBuilder::default()
            .media_type(MediaType::EmptyJSON)
            .size(3u32)
            .digest(Sha256Digest::from_str(
                "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            )?)
            .build()?;
        let mut invalid_blob = oci_dir.create_blob()?;
        invalid_blob.write_all(b"foo")?;
        match invalid_blob
            .complete_verified_as(&test_descriptor)
            .err()
            .unwrap()
        {
            Error::DigestMismatch { expected, found } => {
                assert_eq!(
                    expected.as_ref(),
                    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
                );
                assert_eq!(
                    found.as_ref(),
                    "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
                );
            }
            o => panic!("Unexpected error {o}"),
        }

        Ok(())
    }

    #[test]
    fn test_new_empty_manifest() -> Result<()> {
        let (_td, w) = new_ocidir()?;

        let manifest = w.new_empty_manifest()?.build()?;
        let desc: Descriptor =
            w.insert_manifest(manifest, Some("latest"), oci_image::Platform::default())?;
        assert!(w.has_manifest(&desc).unwrap());

        // We expect two validated blobs: the manifest and the image configuration
        assert_eq!(w.fsck()?, 2);
        Ok(())
    }

    #[test]
    fn test_push_layer_with_history() -> Result<()> {
        let (_td, w) = new_ocidir()?;

        let mut manifest = w.new_empty_manifest()?.build()?;
        let mut config = new_empty_config();
        let root_layer = create_test_layer(&w, b"pretend this is a tarball")?;

        let history = HistoryBuilder::default()
            .created_by("/bin/pretend-tar")
            .build()
            .unwrap();
        w.push_layer_with_history(&mut manifest, &mut config, root_layer, Some(history));
        {
            let history = config.history().as_ref().unwrap().first().unwrap();
            assert_eq!(history.created_by().as_deref().unwrap(), "/bin/pretend-tar");
            assert_eq!(history.created().as_ref(), None);
        }
        Ok(())
    }

    /// Build a manifest descriptor for a foreign platform (used in table-driven tests).
    fn build_foreign_platform_desc(w: &OciDir, arch: Arch, os: Os) -> Result<Descriptor> {
        let manifest = w.new_empty_manifest()?.build()?;
        let manifest_desc = w
            .write_json_blob(&manifest, MediaType::ImageManifest)?
            .build()?;
        w.write_config(new_empty_config())?;

        Ok(oci_image::DescriptorBuilder::default()
            .media_type(MediaType::ImageManifest)
            .digest(manifest_desc.digest().clone())
            .size(manifest_desc.size())
            .platform(
                oci_image::PlatformBuilder::default()
                    .architecture(arch)
                    .os(os)
                    .build()
                    .unwrap(),
            )
            .build()?)
    }

    /// What we expect from an `open_image_this_platform` call.
    enum PlatformExpected {
        /// Should succeed; optionally assert source_index presence.
        Ok { has_source_index: Option<bool> },
        /// Should fail with EmptyImageIndex.
        ErrEmpty,
        /// Should fail with NoMatchingPlatform (optionally check `available` contains a substring).
        ErrNoMatch {
            available_contains: Option<&'static str>,
        },
        /// Should fail with TagNotFound.
        ErrTagNotFound,
    }

    /// Setup function that prepares an OCI directory for a test case.
    type TestSetupFn = Box<dyn Fn(&OciDir) -> Result<()>>;

    /// A single test case for `open_image_this_platform`.
    struct PlatformTestCase {
        name: &'static str,
        setup: TestSetupFn,
        tag: Option<&'static str>,
        expected: PlatformExpected,
    }

    #[test]
    fn test_open_image_this_platform() -> Result<()> {
        let cases: Vec<PlatformTestCase> = vec![
            PlatformTestCase {
                name: "single manifest with platform",
                setup: Box::new(|w| {
                    let mut manifest = w.new_empty_manifest()?.build()?;
                    let config_desc = w.write_config(new_empty_config())?;
                    manifest.set_config(config_desc);
                    w.replace_with_single_manifest(manifest, oci_image::Platform::default())?;
                    Ok(())
                }),
                tag: None,
                expected: PlatformExpected::Ok {
                    has_source_index: Some(false),
                },
            },
            PlatformTestCase {
                name: "single manifest without platform info",
                setup: Box::new(|w| {
                    let manifest = w.new_empty_manifest()?.build()?;
                    let manifest_desc = w
                        .write_json_blob(&manifest, MediaType::ImageManifest)?
                        .build()?;
                    let index = oci_image::ImageIndexBuilder::default()
                        .schema_version(oci_image::SCHEMA_VERSION)
                        .manifests(vec![manifest_desc])
                        .build()?;
                    w.write_index(&index)
                }),
                tag: None,
                expected: PlatformExpected::ErrNoMatch {
                    available_contains: None,
                },
            },
            PlatformTestCase {
                name: "insert with native platform",
                setup: Box::new(|w| {
                    insert_default_manifest(w, None)?;
                    Ok(())
                }),
                tag: None,
                expected: PlatformExpected::Ok {
                    has_source_index: None,
                },
            },
            PlatformTestCase {
                name: "find by tag",
                setup: Box::new(|w| {
                    insert_default_manifest(w, Some("v1.0"))?;
                    Ok(())
                }),
                tag: Some("v1.0"),
                expected: PlatformExpected::Ok {
                    has_source_index: None,
                },
            },
            PlatformTestCase {
                name: "missing tag",
                setup: Box::new(|w| {
                    insert_default_manifest(w, Some("v1.0"))?;
                    Ok(())
                }),
                tag: Some("nonexistent"),
                expected: PlatformExpected::ErrTagNotFound,
            },
            PlatformTestCase {
                name: "empty index",
                setup: Box::new(|w| {
                    let index = oci_image::ImageIndexBuilder::default()
                        .schema_version(oci_image::SCHEMA_VERSION)
                        .manifests(vec![])
                        .build()?;
                    w.write_index(&index)
                }),
                tag: None,
                expected: PlatformExpected::ErrEmpty,
            },
            PlatformTestCase {
                name: "no matching platform (foreign arches only)",
                setup: Box::new(|w| {
                    let desc1 = build_foreign_platform_desc(w, Arch::ARM64, Os::Linux)?;
                    let desc2 = build_foreign_platform_desc(w, Arch::ARM, Os::Linux)?;
                    let index = oci_image::ImageIndexBuilder::default()
                        .schema_version(oci_image::SCHEMA_VERSION)
                        .manifests(vec![desc1, desc2])
                        .build()?;
                    w.write_index(&index)
                }),
                tag: None,
                expected: PlatformExpected::ErrNoMatch {
                    available_contains: Some("linux"),
                },
            },
            PlatformTestCase {
                name: "nested index (manifest list peeling)",
                setup: Box::new(|w| {
                    let mut manifest = w.new_empty_manifest()?.build()?;
                    let config_desc = w.write_config(new_empty_config())?;
                    manifest.set_config(config_desc);
                    let manifest_desc = w
                        .write_json_blob(&manifest, MediaType::ImageManifest)?
                        .platform(oci_image::Platform::default())
                        .build()?;

                    let nested_index = oci_image::ImageIndexBuilder::default()
                        .schema_version(oci_image::SCHEMA_VERSION)
                        .manifests(vec![manifest_desc])
                        .build()?;
                    let mut blob_writer = w.create_blob()?;
                    let nested_json = nested_index.to_string()?;
                    blob_writer.write_all(nested_json.as_bytes())?;
                    let nested_blob = blob_writer.complete()?;

                    let nested_desc = oci_image::DescriptorBuilder::default()
                        .media_type(MediaType::ImageIndex)
                        .digest(nested_blob.sha256().clone())
                        .size(nested_json.len() as u64)
                        .build()?;
                    let top_index = oci_image::ImageIndexBuilder::default()
                        .schema_version(oci_image::SCHEMA_VERSION)
                        .manifests(vec![nested_desc])
                        .build()?;
                    w.write_index(&top_index)
                }),
                tag: None,
                expected: PlatformExpected::Ok {
                    has_source_index: Some(true),
                },
            },
        ];

        for case in &cases {
            let (_td, w) = new_ocidir()?;
            (case.setup)(&w)?;
            let result = w.open_image_this_platform(case.tag);

            let name = case.name;
            match &case.expected {
                PlatformExpected::Ok { has_source_index } => {
                    let resolved = result
                        .unwrap_or_else(|e| panic!("case '{name}': expected Ok, got Err({e})"));
                    if let Some(expect_index) = has_source_index {
                        assert_eq!(
                            resolved.source_index.is_some(),
                            *expect_index,
                            "case '{name}': source_index presence mismatch"
                        );
                    }
                }
                PlatformExpected::ErrEmpty => {
                    assert!(
                        matches!(result, Err(Error::EmptyImageIndex)),
                        "case '{name}': expected EmptyImageIndex, got {result:?}"
                    );
                }
                PlatformExpected::ErrNoMatch { available_contains } => match &result {
                    Err(Error::NoMatchingPlatform { available, .. }) => {
                        if let Some(substr) = available_contains {
                            assert!(
                                available.contains(substr),
                                "case '{name}': expected '{substr}' in available '{available}'"
                            );
                        }
                    }
                    other => panic!("case '{name}': expected NoMatchingPlatform, got {other:?}"),
                },
                PlatformExpected::ErrTagNotFound => {
                    assert!(
                        matches!(result, Err(Error::TagNotFound { .. })),
                        "case '{name}': expected TagNotFound, got {result:?}"
                    );
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_uncompressed_layer() -> Result<()> {
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let w = OciDir::ensure(td.try_clone()?)?;

        let data = b"pretend this is an uncompressed tarball";

        let mut gz = w.create_gzip_layer(None)?;
        gz.write_all(data)?;
        let gz_layer = gz.complete()?;

        let mut uncompressed = w.create_uncompressed_layer()?;
        uncompressed.write_all(data)?;
        let uncompressed_layer = uncompressed.complete()?;

        // sanity-check the gzip blob digest is different from the diffid (i.e.
        // ensure we actually calculated two digests)
        assert_ne!(
            gz_layer.blob.sha256().digest(),
            gz_layer.uncompressed_sha256.digest(),
            "gz layer blob digest should not match diffid"
        );

        // sanity-check the uncompressed blob digest is the same as its diffid
        assert_eq!(
            uncompressed_layer.blob.sha256().digest(),
            uncompressed_layer.uncompressed_sha256.digest(),
            "uncompressed layer blob digest should match diffid"
        );

        // sanity-check their diffids are identical
        assert_eq!(
            gz_layer.uncompressed_sha256.digest(),
            uncompressed_layer.uncompressed_sha256.digest(),
            "uncompressed layer diffid should equal gz layer diffid"
        );

        Ok(())
    }

    /// Test cases for artifact and referrer functionality.
    struct ArtifactTestCase {
        name: &'static str,
        /// Artifact type to use
        artifact_type: &'static str,
        /// Whether to include a content layer
        has_content_layer: bool,
        /// Annotations to set on the artifact manifest
        annotations: Option<HashMap<String, String>>,
    }

    #[test]
    fn test_insert_artifact_manifest() -> Result<()> {
        let cases = vec![
            ArtifactTestCase {
                name: "minimal artifact (no layers, no annotations)",
                artifact_type: "application/vnd.example.sbom.v1",
                has_content_layer: false,
                annotations: None,
            },
            ArtifactTestCase {
                name: "artifact with content layer",
                artifact_type: "application/vnd.example.signature.v1",
                has_content_layer: true,
                annotations: None,
            },
            ArtifactTestCase {
                name: "artifact with annotations",
                artifact_type: "application/vnd.example.attestation.v1",
                has_content_layer: false,
                annotations: Some(
                    [
                        (
                            "org.opencontainers.image.created".into(),
                            "2024-01-01T00:00:00Z".into(),
                        ),
                        ("com.example.key".into(), "value".into()),
                    ]
                    .into_iter()
                    .collect(),
                ),
            },
        ];

        for case in &cases {
            let (_td, w) = new_ocidir()?;
            let name = case.name;

            // Create a base image to reference
            let (_, subject_desc) = insert_default_manifest(&w, Some("base"))?;

            // Prepare layers
            let layers = if case.has_content_layer {
                let mut blob = w.create_blob()?;
                blob.write_all(b"artifact content")?;
                let blob = blob.complete()?;
                vec![
                    blob.descriptor()
                        .media_type(MediaType::Other("application/vnd.example.data".into()))
                        .build()
                        .unwrap(),
                ]
            } else {
                vec![]
            };

            let artifact_type = MediaType::Other(case.artifact_type.into());
            let desc = w.insert_artifact_manifest(
                subject_desc.clone(),
                artifact_type.clone(),
                layers,
                case.annotations.clone(),
            )?;

            // Verify the descriptor in the index carries artifact_type
            assert_eq!(
                desc.artifact_type().as_ref(),
                Some(&artifact_type),
                "case '{name}': descriptor should carry artifact_type"
            );

            // Verify the descriptor does NOT carry a platform field
            assert!(
                desc.platform().is_none(),
                "case '{name}': artifact descriptor should not have platform"
            );

            // Verify annotations are propagated to the descriptor
            if let Some(expected_annos) = &case.annotations {
                let desc_annos = desc
                    .annotations()
                    .as_ref()
                    .expect("annotations should be set");
                for (k, v) in expected_annos {
                    assert_eq!(
                        desc_annos.get(k),
                        Some(v),
                        "case '{name}': annotation '{k}' should be propagated"
                    );
                }
            }

            // Verify the manifest blob was written correctly
            let manifest: ImageManifest = w.read_json_blob(&desc)?;
            assert_eq!(
                manifest.artifact_type().as_ref(),
                Some(&artifact_type),
                "case '{name}': manifest should have artifact_type"
            );
            assert_eq!(
                manifest.subject().as_ref().map(|s| s.digest()),
                Some(subject_desc.digest()),
                "case '{name}': manifest subject should match"
            );
            assert_eq!(
                manifest.config().media_type(),
                &MediaType::EmptyJSON,
                "case '{name}': config should be empty descriptor"
            );

            // Verify layers
            if case.has_content_layer {
                assert_eq!(
                    manifest.layers().len(),
                    1,
                    "case '{name}': should have one content layer"
                );
                assert_ne!(
                    manifest.layers()[0].media_type(),
                    &MediaType::EmptyJSON,
                    "case '{name}': content layer should not be empty"
                );
            } else {
                // Should have single empty layer per spec guidance
                assert_eq!(
                    manifest.layers().len(),
                    1,
                    "case '{name}': should have one (empty) layer"
                );
                assert_eq!(
                    manifest.layers()[0].media_type(),
                    &MediaType::EmptyJSON,
                    "case '{name}': layer should be empty descriptor"
                );
            }

            // Verify fsck passes with artifact manifest
            let validated = w.fsck()?;
            assert!(
                validated >= 4,
                "case '{name}': fsck should validate at least 4 blobs, got {validated}: 
                 base manifest + base config + artifact manifest + empty config = 4 minimum"
            );
        }
        Ok(())
    }

    #[test]
    fn test_find_referrers() -> Result<()> {
        let (_td, w) = new_ocidir()?;

        // Create a base image
        let (_, subject_desc) = insert_default_manifest(&w, Some("base"))?;

        // Insert multiple artifact manifests referencing the base image
        let sbom_type = MediaType::Other("application/vnd.example.sbom.v1".into());
        let sig_type = MediaType::Other("application/vnd.example.signature.v1".into());

        let sbom_desc = w.insert_artifact_manifest(
            subject_desc.clone(),
            sbom_type.clone(),
            vec![],
            Some(
                [("org.example.format".into(), "json".into())]
                    .into_iter()
                    .collect(),
            ),
        )?;

        let sig_desc =
            w.insert_artifact_manifest(subject_desc.clone(), sig_type.clone(), vec![], None)?;

        // Create a second base image (with a layer so it has a different digest)
        // that has no referrers
        let root_layer = create_test_layer(&w, b"other image content")?;
        let mut other_manifest = w.new_empty_manifest()?.build()?;
        let mut other_config = new_empty_config();
        w.push_layer(
            &mut other_manifest,
            &mut other_config,
            root_layer,
            "root",
            None,
        );
        let other_desc = w.insert_manifest_and_config(
            other_manifest,
            other_config,
            Some("other"),
            Platform::default(),
        )?;

        // Find all referrers for the first subject
        let referrers = w.find_referrers(subject_desc.digest(), None)?;
        assert_eq!(referrers.len(), 2, "should find 2 referrers");

        // Verify the referrer descriptors match what we inserted
        let referrer_digests: HashSet<_> = referrers.iter().map(|d| d.digest().clone()).collect();
        assert!(
            referrer_digests.contains(sbom_desc.digest()),
            "should find SBOM referrer"
        );
        assert!(
            referrer_digests.contains(sig_desc.digest()),
            "should find signature referrer"
        );

        // Verify artifact_type and annotations are on the referrer descriptors
        for r in &referrers {
            assert!(
                r.artifact_type().is_some(),
                "referrer descriptor should carry artifact_type"
            );
        }

        // Verify the SBOM referrer's annotations were propagated
        let sbom_referrer = referrers
            .iter()
            .find(|r| r.digest() == sbom_desc.digest())
            .expect("SBOM referrer should exist");
        let sbom_annos = sbom_referrer
            .annotations()
            .as_ref()
            .expect("SBOM referrer should have annotations");
        assert_eq!(
            sbom_annos.get("org.example.format"),
            Some(&"json".to_string()),
            "SBOM referrer should carry manifest annotations"
        );

        // Filter by artifact_type
        let sbom_only = w.find_referrers(subject_desc.digest(), Some(&sbom_type))?;
        assert_eq!(sbom_only.len(), 1, "should find 1 SBOM referrer");
        assert_eq!(
            sbom_only[0].artifact_type().as_ref(),
            Some(&sbom_type),
            "filtered referrer should be SBOM type"
        );

        let sig_only = w.find_referrers(subject_desc.digest(), Some(&sig_type))?;
        assert_eq!(sig_only.len(), 1, "should find 1 signature referrer");

        // No referrers for the other image
        let no_referrers = w.find_referrers(other_desc.digest(), None)?;
        assert!(
            no_referrers.is_empty(),
            "other image should have no referrers"
        );

        // No referrers for a nonexistent digest
        let fake_digest = Digest::from(Sha256Digest::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )?);
        let no_referrers = w.find_referrers(&fake_digest, None)?;
        assert!(
            no_referrers.is_empty(),
            "nonexistent digest should have no referrers"
        );

        // Filter with a type that has no matches
        let unknown_type = MediaType::Other("application/vnd.example.unknown".into());
        let no_match = w.find_referrers(subject_desc.digest(), Some(&unknown_type))?;
        assert!(
            no_match.is_empty(),
            "unknown type filter should return empty"
        );

        Ok(())
    }

    #[test]
    fn test_insert_manifest_propagates_artifact_type() -> Result<()> {
        let (_td, w) = new_ocidir()?;

        // Create a base image
        let (_, subject_desc) = insert_default_manifest(&w, Some("base"))?;

        // Create a manifest with subject and artifact_type, inserted via
        // the regular insert_manifest path
        let artifact_type = MediaType::Other("application/vnd.example.sbom.v1".into());
        let empty_config = w.empty_config_descriptor()?;
        let manifest = oci_image::ImageManifestBuilder::default()
            .schema_version(oci_image::SCHEMA_VERSION)
            .config(empty_config.clone())
            .layers(vec![empty_config])
            .artifact_type(artifact_type.clone())
            .subject(subject_desc)
            .annotations(
                [("com.example.key".into(), "value".into())]
                    .into_iter()
                    .collect::<HashMap<String, String>>(),
            )
            .build()?;

        let desc = w.insert_manifest(manifest, None, Platform::default())?;

        // The descriptor should have artifact_type propagated
        assert_eq!(
            desc.artifact_type().as_ref(),
            Some(&artifact_type),
            "descriptor should carry artifact_type from manifest"
        );

        // The descriptor should have annotations propagated (from the manifest)
        let annos = desc
            .annotations()
            .as_ref()
            .expect("should have annotations");
        assert_eq!(
            annos.get("com.example.key"),
            Some(&"value".to_string()),
            "descriptor should carry annotations from manifest"
        );

        Ok(())
    }

    #[test]
    fn test_artifact_type_fallback_to_config_media_type() -> Result<()> {
        let (_td, w) = new_ocidir()?;

        // Create a base image
        let (_, subject_desc) = insert_default_manifest(&w, Some("base"))?;

        // Create a manifest with subject but WITHOUT explicit artifact_type.
        // Per the spec, the descriptor's artifact_type should fall back to
        // config.mediaType.
        let config_type = MediaType::Other("application/vnd.example.config.v1+json".into());

        // Write a config blob with our custom type
        let mut blob = w.create_blob()?;
        blob.write_all(b"{}")?;
        let config_blob = blob.complete()?;
        let config_desc = config_blob
            .descriptor()
            .media_type(config_type.clone())
            .build()
            .unwrap();

        let manifest = oci_image::ImageManifestBuilder::default()
            .schema_version(oci_image::SCHEMA_VERSION)
            .config(config_desc)
            .layers(vec![])
            .subject(subject_desc)
            .build()?;

        let desc = w.insert_manifest(manifest, None, Platform::default())?;

        // Without explicit artifact_type, should fall back to config.mediaType
        assert_eq!(
            desc.artifact_type().as_ref(),
            Some(&config_type),
            "descriptor artifact_type should fall back to config.mediaType"
        );

        Ok(())
    }

    #[test]
    fn test_artifact_fsck() -> Result<()> {
        let (_td, w) = new_ocidir()?;

        // Create a base image
        let (_, subject_desc) = insert_default_manifest(&w, Some("base"))?;

        // Insert an artifact referencing the base
        let artifact_type = MediaType::Other("application/vnd.example.sbom.v1".into());

        // Also write a real content blob
        let mut blob = w.create_blob()?;
        blob.write_all(b"sbom content here")?;
        let content_blob = blob.complete()?;
        let content_desc = content_blob
            .descriptor()
            .media_type(MediaType::Other("application/vnd.example.sbom".into()))
            .build()
            .unwrap();

        w.insert_artifact_manifest(subject_desc, artifact_type, vec![content_desc], None)?;

        // fsck should pass with artifact manifests in the index
        let validated = w.fsck()?;
        // base manifest + base config + artifact manifest + empty config + content blob = 5
        assert_eq!(validated, 5, "fsck should validate exactly 5 blobs");

        Ok(())
    }
}
