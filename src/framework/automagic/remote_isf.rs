//! An index of symbol files published on the internet.
//!
//! A symbol file names the kernel build it describes, and an image names the
//! same build, so matching the two is how an image gets its symbols. When
//! neither a local pack nor the Microsoft symbol server has the one that is
//! needed, a public index can be consulted: a small JSON document maps each
//! known kernel identifier to a URL the file can be fetched from.
//!
//! The format is the one upstream reads for `--remote-isf-url`, version 1: an
//! object whose `version` is 1, whose per-OS keys (`windows`, `linux`, `mac`)
//! each hold a map from a base64-encoded identifier to a list of URLs, and
//! whose optional `additional` key lists further indexes of the same shape.
//!
//! Derived from Volatility 3, Copyright Volatility Foundation, licensed under
//! the Volatility Software License 1.0.

use std::collections::HashMap;
use std::io::Read;

use base64::Engine as _;

use crate::error::{Result, VolatilityError};
use crate::framework::symbols::intermed::{decompress, SymbolLocation};

/// The version of the format this reads. Anything else is refused rather than
/// guessed at, which is what upstream does.
const SUPPORTED_VERSION: u64 = 1;

/// How deep `additional` links are followed.
///
/// A published index nests one level in practice. The limit exists so a
/// misconfigured index that points at itself cannot spin forever.
const MAX_DEPTH: usize = 4;

/// A fetched index: identifier to the URLs that serve it.
#[derive(Debug, Default, Clone)]
pub struct RemoteIndex {
    entries: HashMap<String, Vec<String>>,
}

impl RemoteIndex {
    /// Read an index from a URL, following the `additional` links it names.
    ///
    /// The URL may be an ordinary `https://` location or a local `file://` one,
    /// which is what makes the feature testable without a network.
    pub fn from_url(url: &str) -> Result<Self> {
        let mut index = Self::default();
        index.extend(url, 0)?;
        Ok(index)
    }

    /// Read an index, from the cache where one was fetched recently.
    ///
    /// The published index is several megabytes and changes only when a
    /// distribution publishes a new kernel build, so fetching it on every run
    /// would spend more time on the index than on the image. An index younger
    /// than [`INDEX_CACHE_PERIOD`] is used as it stands.
    pub fn from_url_cached(url: &str) -> Result<Self> {
        let (data, _fresh) = cached_fetch(url, "index", INDEX_CACHE_PERIOD)?;
        let mut index = Self::from_json(&data)?;
        // The links are cached by the same rule, so a fresh index brings its
        // links with it rather than fetching them again.
        if let Ok(document) = serde_json::from_slice::<serde_json::Value>(&data) {
            if let Some(additional) = document.get("additional").and_then(|v| v.as_array()) {
                for location in additional.iter().filter_map(|value| value.as_str()) {
                    if let Ok(more) = Self::from_url_cached(location) {
                        for (identifier, urls) in more.entries {
                            index.entries.entry(identifier).or_insert(urls);
                        }
                    }
                }
            }
        }
        Ok(index)
    }

    /// Parse an index already in hand.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        let document: serde_json::Value = serde_json::from_slice(data).map_err(|error| {
            VolatilityError::Other(format!("The remote symbol index is not valid JSON: {error}"))
        })?;

        let version = document.get("version").and_then(|value| value.as_u64());
        if version != Some(SUPPORTED_VERSION) {
            return Err(VolatilityError::Other(format!(
                "Unsupported version for remote identifier list format: {}",
                version.map(|v| v.to_string()).unwrap_or_else(|| "none".to_string())
            )));
        }

        let mut entries = HashMap::new();
        // Every key other than the one carrying the version and the one naming
        // further indexes holds identifiers for an operating system. Reading
        // them all rather than one at a time means a single fetch answers for
        // whichever OS the image turns out to be.
        for (key, value) in document.as_object().into_iter().flatten() {
            if key == "version" || key == "additional" {
                continue;
            }
            let Some(identifiers) = value.as_object() else {
                continue;
            };
            for (identifier, locations) in identifiers {
                let Some(locations) = locations.as_array() else {
                    continue;
                };
                // The identifier is base64 in the published format, but an
                // index may also carry it plainly. A plain one is kept as it
                // is rather than dropped.
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(identifier.trim())
                    .ok()
                    .and_then(|raw| String::from_utf8(raw).ok())
                    .map(|decoded| strip_terminators(&decoded))
                    .unwrap_or_else(|| strip_terminators(&identifier));
                let urls: Vec<String> = locations
                    .iter()
                    .filter_map(|location| location.as_str().map(str::to_string))
                    .collect();
                if !decoded.is_empty() && !urls.is_empty() {
                    entries.insert(decoded, urls);
                }
            }
        }

        Ok(Self { entries })
    }

    /// How many identifiers the index knows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The URLs serving a given identifier, if the index names any.
    pub fn lookup(&self, identifier: &str) -> Option<&Vec<String>> {
        self.entries.get(identifier)
    }

    /// Whether the index knows this identifier, directly or by a prefix.
    ///
    /// A banner read out of memory can be truncated by the page it sits in, so
    /// a known identifier that starts with what was found still counts — the
    /// same accommodation `BannerIndex` makes for local files.
    pub fn knows(&self, identifier: &str) -> bool {
        self.lookup(identifier).is_some() || self.prefix_lookup(identifier).is_some()
    }

    pub fn prefix_lookup(&self, identifier: &str) -> Option<&Vec<String>> {
        let trimmed = identifier.trim();
        if trimmed.is_empty() {
            return None;
        }
        self.entries
            .iter()
            .find(|(known, _)| known.starts_with(trimmed) || trimmed.starts_with(known.as_str()))
            .map(|(_, urls)| urls)
    }

    fn extend(&mut self, url: &str, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            log::debug!("Not following '{url}': the index nests deeper than {MAX_DEPTH}");
            return Ok(());
        }
        let data = fetch(url)?;
        let parsed = Self::from_json(&data)?;

        // Follow the links this index names before taking its own entries, so
        // a link that fails to load does not lose the rest.
        let additional = serde_json::from_slice::<serde_json::Value>(&data)
            .ok()
            .and_then(|document| document.get("additional").cloned())
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_default();
        for location in additional.iter().filter_map(|value| value.as_str()) {
            if let Err(error) = self.extend(location, depth + 1) {
                log::debug!("Remote index '{location}' could not be read: {error}");
            }
        }

        for (identifier, urls) in parsed.entries {
            self.entries.insert(identifier, urls);
        }
        Ok(())
    }
}

/// A banner as an index records it, reduced to the text an image holds.
///
/// `dwarf2json` writes a Linux banner followed by a newline and a NUL; a banner
/// read out of memory ends at the NUL and never carries either. Both are
/// stripped, and in that order: the newline sits before the NUL, so removing
/// the NUL first would leave the newline in place and stop the two matching.
fn strip_terminators(value: &str) -> String {
    value.trim_end_matches(['\n', '\0']).to_string()
}

/// How long a fetched index is trusted before it is fetched again.
const INDEX_CACHE_PERIOD: std::time::Duration = std::time::Duration::from_secs(60 * 60 * 24 * 7);

/// Read a URL, keeping the answer on disk so the next run need not ask again.
///
/// Returns the bytes and whether they came from the cache. A `file://` URL is
/// read directly rather than copied, since it is already local. A failed
/// fetch falls back to a stale copy when one exists, because a day-old index
/// still describes every kernel it described yesterday.
fn cached_fetch(url: &str, kind: &str, period: std::time::Duration) -> Result<(Vec<u8>, bool)> {
    let cached = crate::framework::cache::entry(kind)
        .map(|directory| directory.join(file_name_for(url)));

    if let Some(path) = &cached {
        if let Ok(metadata) = std::fs::metadata(path) {
            let fresh = metadata
                .modified()
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .map(|age| age < period)
                .unwrap_or(false);
            if fresh {
                if let Ok(data) = std::fs::read(path) {
                    log::debug!("Using the cached copy of {url}");
                    return Ok((data, true));
                }
            }
        }
    }

    match fetch(url) {
        Ok(data) => {
            if let Some(path) = &cached {
                if let Some(directory) = path.parent() {
                    let _ = std::fs::create_dir_all(directory);
                }
                let _ = std::fs::write(path, &data);
            }
            Ok((data, false))
        }
        Err(error) => match cached.map(std::fs::read) {
            Some(Ok(data)) => {
                log::debug!("{error}; using the older copy that is on disk");
                Ok((data, true))
            }
            _ => Err(error),
        },
    }
}

/// Read a URL, whether it names a local file or somewhere on the network.
pub fn fetch(url: &str) -> Result<Vec<u8>> {    if crate::framework::cache::offline() {
        return Err(VolatilityError::Other(format!(
            "Volatility 3 is offline: unable to access {url}"
        )));
    }

    if let Some(path) = url.strip_prefix("file://") {
        let path = path.trim_start_matches('/');
        return std::fs::read(path)
            .map_err(|error| VolatilityError::Other(format!("Could not read {url}: {error}")));
    }

    let mut response = ureq::get(url)
        .call()
        .map_err(|error| VolatilityError::Other(format!("Could not fetch {url}: {error}")))?;
    let mut data = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut data)
        .map_err(|error| VolatilityError::Other(format!("Could not read {url}: {error}")))?;
    Ok(data)
}

/// Fetch a symbol file from one of the URLs an index gives for it, and keep it.
///
/// The file is written into the caller's cache under a name derived from the
/// identifier, so the next run finds it on disk without touching the network.
/// A URL that fails is tried in turn, since a publisher may list a mirror.
pub fn download(urls: &[String], identifier: &str) -> Result<SymbolLocation> {
    let destination = crate::framework::cache::entry("remote-isf").ok_or_else(|| {
        VolatilityError::Other("No cache directory is available to keep symbols in".to_string())
    })?;

    let name = file_name_for(identifier);

    // A file fetched on an earlier run is used as it stands. The extension is
    // part of the name, so each candidate is checked rather than assuming the
    // one the first URL would have produced.
    if destination.is_dir() {
        for extension in [".json.xz", ".json.gz", ".json.bz2", ".json", ".xz", ".gz", ".bz2"] {
            let path = destination.join(format!("{name}{extension}"));
            if path.is_file() {
                log::debug!("Using the symbols already fetched at {}", path.display());
                return Ok(SymbolLocation::File(path));
            }
        }
    }

    std::fs::create_dir_all(&destination).map_err(|error| {
        VolatilityError::Io(format!(
            "Could not create {}: {error}",
            destination.display()
        ))
    })?;

    let mut last_error = None;
    for url in urls {
        log::info!("Fetching symbols from {url}");
        match fetch(url) {
            Ok(data) => {
                // The published files are usually compressed. The extension
                // decides how they are decompressed, so the name has to keep
                // it: the payload is stored exactly as it arrived.
                let extension = extension_of(url);
                let path = destination.join(format!("{name}{extension}"));
                // A file that decompresses to nothing usable is not a symbol
                // file, however it arrived, so it is checked before it is
                // kept: a truncated download must not poison the cache.
                decompress(&path, data.clone()).map_err(|error| {
                    VolatilityError::Other(format!("{url} is not a symbol file: {error}"))
                })?;
                std::fs::write(&path, &data).map_err(|error| {
                    VolatilityError::Io(format!("Could not write {}: {error}", path.display()))
                })?;
                return Ok(SymbolLocation::File(path));
            }
            Err(error) => {
                log::debug!("{error}");
                last_error = Some(error);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        VolatilityError::Other(format!("No location was given for {identifier}"))
    }))
}

/// A file name that is safe to write and stable for an identifier.
fn file_name_for(identifier: &str) -> String {
    let mut name: String = identifier
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '.' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect();
    if name.len() > 120 {
        name.truncate(120);
    }
    if name.is_empty() {
        name = "symbols".to_string();
    }
    name
}

/// The compression extension a URL's file carries, if any.
fn extension_of(url: &str) -> &'static str {
    let lower = url.split(['?', '#']).next().unwrap_or(url).to_ascii_lowercase();
    if lower.ends_with(".json.xz") {
        ".json.xz"
    } else if lower.ends_with(".xz") {
        ".xz"
    } else if lower.ends_with(".json.gz") {
        ".json.gz"
    } else if lower.ends_with(".gz") {
        ".gz"
    } else if lower.ends_with(".json.bz2") {
        ".json.bz2"
    } else if lower.ends_with(".bz2") {
        ".bz2"
    } else if lower.ends_with(".zip") {
        ".zip"
    } else {
        ".json"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document in the shape the Abyss-W4tcher repository publishes.
    fn published_example() -> Vec<u8> {
        let banner = "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) \
                      (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.57-3+deb7u2";
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{banner}\n"));
        serde_json::json!({
            "version": 1,
            "linux": {
                encoded: [
                    "https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/\
                     isf-Debian-amd64-3.2.0/Debian_3.2.0-4-amd64_3.2.57-3%2Bdeb7u2_amd64.json.xz"
                ]
            }
        })
        .to_string()
        .into_bytes()
    }

    #[test]
    fn reads_the_published_format_and_unwraps_the_banner() {
        let index = RemoteIndex::from_json(&published_example()).unwrap();
        assert_eq!(index.len(), 1);

        // The identifier in the document is base64 over a banner with a
        // trailing newline. What is stored is the banner itself, so a banner
        // read out of an image can be looked up directly.
        let banner = "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) \
                      (gcc version 4.6.3 (Debian 4.6.3-14) ) #1 SMP Debian 3.2.57-3+deb7u2";
        let urls = index.lookup(banner).expect("the banner should be known");
        assert_eq!(urls.len(), 1);
        assert!(urls[0].ends_with("_amd64.json.xz"));
    }

    #[test]
    fn a_dwarf2json_identifier_ending_in_a_nul_still_matches() {
        // dwarf2json ends a Linux banner with "\x00\n"; neither byte can appear
        // in a banner read from memory.
        let banner = "Linux version 6.5.0-41-generic (buildd@lcy02) #41-Ubuntu";
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{banner}\0\n"));
        let document = serde_json::json!({
            "version": 1,
            "linux": { encoded: ["https://example.invalid/x.json.xz"] }
        })
        .to_string()
        .into_bytes();

        let index = RemoteIndex::from_json(&document).unwrap();
        assert!(index.knows(banner));
    }

    /// The published index ends its identifiers with a newline *then* a NUL.
    /// Stripping only the NUL leaves the newline behind, and every lookup
    /// misses, so the exact ordering the real data uses is checked here.
    #[test]
    fn an_identifier_ending_newline_then_nul_matches_exactly() {
        let banner = "Linux version 3.2.0-4-amd64 (debian-kernel@lists.debian.org) \
                      (gcc version 4.6.3 (Debian 4.6.3-9) ) #1 SMP Debian 3.2.29-1";
        let banner = banner.split_whitespace().collect::<Vec<_>>().join(" ");
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{banner}\n\0"));
        let document = serde_json::json!({
            "version": 1,
            "linux": { encoded: ["https://example.invalid/x.json.xz"] }
        })
        .to_string()
        .into_bytes();

        let index = RemoteIndex::from_json(&document).unwrap();
        assert!(
            index.lookup(&banner).is_some(),
            "the exact banner should be found, not just a prefix of it"
        );
    }

    #[test]
    fn a_banner_with_trailing_whitespace_inside_is_left_alone() {
        // Only terminators are removed: a run of spaces inside the banner is
        // part of it and must survive, or it would stop matching.
        let banner = "Linux version 5.15.0 (a  b) #1 SMP";
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{banner}\n\0"));
        let document = serde_json::json!({
            "version": 1,
            "linux": { encoded: ["https://example.invalid/x.json.xz"] }
        })
        .to_string()
        .into_bytes();

        let index = RemoteIndex::from_json(&document).unwrap();
        let urls = index.lookup(banner).expect("found");
        assert_eq!(urls.len(), 1);
    }

    #[test]
    fn a_truncated_banner_still_finds_its_entry() {
        let banner = "Linux version 6.8.0-45-generic (buildd@lcy02) #45-Ubuntu";
        let encoded = base64::engine::general_purpose::STANDARD.encode(banner);
        let document = serde_json::json!({
            "version": 1,
            "linux": { encoded: ["https://example.invalid/x.json.xz"] }
        })
        .to_string()
        .into_bytes();

        let index = RemoteIndex::from_json(&document).unwrap();
        // A banner cut off by the end of the page it sits in is still useful.
        assert!(index.knows("Linux version 6.8.0-45-generic (buildd@lcy02) #45-"));
    }

    #[test]
    fn every_operating_system_is_read_at_once() {
        let windows = base64::engine::general_purpose::STANDARD.encode("Windows.1.0.0.0");
        let linux = base64::engine::general_purpose::STANDARD.encode("Linux version 5.0");
        let document = serde_json::json!({
            "version": 1,
            "windows": { windows: ["https://example.invalid/w.json.xz"] },
            "linux": { linux: ["https://example.invalid/l.json.xz"] }
        })
        .to_string()
        .into_bytes();

        let index = RemoteIndex::from_json(&document).unwrap();
        assert!(index.knows("Windows.1.0.0.0"));
        assert!(index.knows("Linux version 5.0"));
    }

    #[test]
    fn a_document_of_another_version_is_refused() {
        let document = serde_json::json!({ "version": 2, "linux": {} })
            .to_string()
            .into_bytes();
        let error = RemoteIndex::from_json(&document).unwrap_err().to_string();
        assert!(error.contains("Unsupported version"), "{error}");
    }

    #[test]
    fn a_document_that_is_not_json_is_refused() {
        assert!(RemoteIndex::from_json(b"not json").is_err());
    }

    #[test]
    fn the_compression_extension_is_taken_from_the_url() {
        assert_eq!(extension_of("https://x/y.json.xz"), ".json.xz");
        assert_eq!(extension_of("https://x/y.json.gz?download=1"), ".json.gz");
        assert_eq!(extension_of("https://x/y.gz"), ".gz");
        assert_eq!(extension_of("https://x/y.json"), ".json");
        assert_eq!(extension_of("https://x/y.zip"), ".zip");
    }

    #[test]
    fn an_identifier_becomes_a_file_name_that_can_be_written() {
        // The identifier holds spaces, parentheses and slashes, none of which
        // belong in a file name on every platform.
        let name = file_name_for("Linux version 5.0 (a/b) #1");
        assert!(!name.contains('/'));
        assert!(!name.contains(' '));
        assert!(!name.contains('('));
        assert!(name.starts_with("Linux_version_5.0"));
    }
}
