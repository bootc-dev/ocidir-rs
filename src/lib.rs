#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use canon_json::CanonicalFormatter;
use cap_std::fs::{Dir, DirBuilderExt};
use cap_std_ext::cap_tempfile;
use cap_std_ext::dirext::CapStdExtDirExt;
use flate2::write::GzEncoder;
use oci_image::MediaType;
use oci_spec::image::{
    self as oci_image, Descriptor, Digest, ImageConfiguration, ImageIndex, ImageManifest,
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
    #[error("Unexpected media type {media_type}")]
    /// Returned when there's an unexpected media type
    UnexpectedMediaType {
        /// The unexpected media type that was encountered
        media_type: MediaType,
    },
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
        match config.history_mut() {
            Some(h) => h.push(history),
            None => {
                config.set_history(Some(vec![history]));
            }
        }
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
            .build()
            .unwrap())
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
    pub fn insert_manifest(
        &self,
        manifest: oci_image::ImageManifest,
        tag: Option<&str>,
        platform: oci_image::Platform,
    ) -> Result<Descriptor> {
        let mut manifest = self
            .write_json_blob(&manifest, MediaType::ImageManifest)?
            .platform(platform)
            .build()
            .unwrap();
        if let Some(tag) = tag {
            let annotations: HashMap<_, _> = [(OCI_TAG_ANNOTATION.to_string(), tag.to_string())]
                .into_iter()
                .collect();
            manifest.set_annotations(Some(annotations));
        }

        let index = match self.read_index() {
            Ok(mut index) => {
                let mut manifests = index.manifests().clone();
                if let Some(tag) = tag {
                    manifests.retain(|d| !Self::descriptor_is_tagged(d, tag));
                }
                manifests.push(manifest.clone());
                index.set_manifests(manifests);
                index
            }
            Err(Error::MissingImageIndex) => oci_image::ImageIndexBuilder::default()
                .schema_version(oci_image::SCHEMA_VERSION)
                .manifests(vec![manifest.clone()])
                .build()?,
            Err(e) => {
                return Err(e);
            }
        };

        self.dir
            .atomic_replace_with("index.json", |mut w| -> Result<()> {
                let mut ser =
                    serde_json::Serializer::with_formatter(&mut w, CanonicalFormatter::new());
                index.serialize(&mut ser)?;
                Ok(())
            })?;
        Ok(manifest)
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
        self.dir
            .atomic_replace_with("index.json", |mut w| -> Result<()> {
                let mut ser =
                    serde_json::Serializer::with_formatter(&mut w, CanonicalFormatter::new());
                index_data.serialize(&mut ser)?;
                Ok(())
            })?;
        Ok(())
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

    /// Verify a single manifest and all of its referenced objects.
    /// Skips already validated blobs referenced by digest in `validated`,
    /// and updates that set with ones we did validate.
    fn fsck_one_manifest(
        &self,
        manifest: &ImageManifest,
        validated: &mut HashSet<Box<str>>,
    ) -> Result<()> {
        let config_digest = sha256_of_descriptor(manifest.config())?;
        match manifest.config().media_type() {
            MediaType::ImageConfig => {
                let _: ImageConfiguration = self.read_json_blob(manifest.config())?;
            }
            MediaType::EmptyJSON => {
                let _: EmptyDescriptor = self.read_json_blob(manifest.config())?;
            }
            media_type => {
                return Err(Error::UnexpectedMediaType {
                    media_type: media_type.clone(),
                });
            }
        }
        validated.insert(config_digest.into());
        for layer in manifest.layers() {
            let expected = sha256_of_descriptor(layer)?;
            if validated.contains(expected) {
                continue;
            }
            let mut f = self.read_blob(layer)?;
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
            target: Some(BufWriter::new(cap_tempfile::TempFile::new(ocidir)?)),
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

impl<'a, W> LayerWriter<'a, W>
where
    W: WriteComplete<BlobWriter<'a>>,
{
    /// Create a new LayerWriter with the given inner writer and media type
    pub fn new(inner: W, media_type: oci_image::MediaType) -> Self {
        Self {
            inner: Sha256Writer::new(inner),
            media_type,
            marker: PhantomData,
        }
    }

    /// Complete the layer writing and return the layer descriptor
    pub fn complete(self) -> Result<Layer> {
        let (uncompressed_sha256, enc) = self.inner.finish();
        let blob = enc.complete()?.complete()?;
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

/// Wraps a writer and calculates the sha256 digest of data written to the inner writer
struct Sha256Writer<W> {
    inner: W,
    sha: openssl::sha::Sha256,
}

impl<W> Sha256Writer<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            sha: openssl::sha::Sha256::new(),
        }
    }

    /// Return the hex encoded sha256 digest of the written data, and the underlying writer
    pub(crate) fn finish(self) -> (Sha256Digest, W) {
        let digest = hex::encode(self.sha.finish());
        (Sha256Digest::from_str(&digest).unwrap(), self.inner)
    }
}

impl<W> Write for Sha256Writer<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = self.inner.write(buf)?;
        self.sha.update(&buf[..len]);
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use cap_std::fs::OpenOptions;
    use oci_spec::image::HistoryBuilder;

    use super::*;

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
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let w = OciDir::ensure(td.try_clone()?)?;
        let mut layerw = w.create_gzip_layer(None)?;
        layerw.write_all(b"pretend this is a tarball")?;
        let root_layer = layerw.complete()?;
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
        let mut config = oci_image::ImageConfigurationBuilder::default()
            .build()
            .unwrap();
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

        let mut layerw = w.create_gzip_layer(None)?;
        layerw.write_all(b"pretend this is an updated tarball")?;
        let root_layer = layerw.complete()?;
        let mut manifest = w.new_empty_manifest()?.build()?;
        let mut config = oci_image::ImageConfigurationBuilder::default()
            .build()
            .unwrap();
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
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let oci_dir = OciDir::ensure(td.try_clone()?)?;

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
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let w = OciDir::ensure(td.try_clone()?)?;

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
        let td = cap_tempfile::tempdir(cap_std::ambient_authority())?;
        let w = OciDir::ensure(td.try_clone()?)?;

        let mut manifest = w.new_empty_manifest()?.build()?;
        let mut config = oci_image::ImageConfigurationBuilder::default()
            .build()
            .unwrap();
        let mut layerw = w.create_gzip_layer(None)?;
        layerw.write_all(b"pretend this is a tarball")?;
        let root_layer = layerw.complete()?;

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
}
