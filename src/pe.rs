use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
};
include!("signatures.rs");

pub fn pattern(text: &str) -> Result<Vec<Option<u8>>> {
    text.split_whitespace()
        .map(|token| match token {
            "?" | "??" => Ok(None),
            _ => Ok(Some(u8::from_str_radix(token, 16)?)),
        })
        .collect()
}

pub fn matches(data: &[u8], signature: &[Option<u8>]) -> bool {
    data.len() >= signature.len()
        && signature
            .iter()
            .zip(data)
            .all(|(expected, actual)| expected.is_none_or(|b| b == *actual))
}

struct Section {
    rva: u32,
    raw: usize,
    size: usize,
    executable: bool,
}

pub struct Image {
    data: Vec<u8>,
    pub hash: String,
    sections: Vec<Section>,
    starts: HashSet<u32>,
    methods: BTreeMap<&'static str, u32>,
    exports: (u32, u32),
}

impl Image {
    pub fn read(path: &Path) -> Result<Self> {
        Self::parse(std::fs::read(path).with_context(|| format!("Reading {}", path.display()))?)
    }

    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let mut image = Self {
            hash: hex::encode(Sha256::digest(&data)),
            data,
            sections: Vec::new(),
            starts: HashSet::new(),
            methods: BTreeMap::new(),
            exports: (0, 0),
        };
        ensure!(image.u16(0)? == 0x5a4d, "Missing DOS header");
        let pe = image.u32(0x3c)? as usize;
        ensure!(
            image.u32(pe)? == 0x4550 && image.u16(pe + 4)? == 0x8664,
            "Expected an AMD64 PE DLL"
        );
        ensure!(image.u16(pe + 22)? & 0x2000 != 0, "Image is not a DLL");
        let optional = pe + 24;
        let size = image.u16(pe + 20)? as usize;
        image.bytes(optional, size)?;
        ensure!(
            size >= 144 && image.u16(optional)? == 0x20b && image.u32(optional + 108)? >= 4,
            "Missing PE32+ exception directory"
        );
        image.exports = (image.u32(optional + 112)?, image.u32(optional + 116)?);
        let table = optional + size;
        for i in 0..image.u16(pe + 6)? as usize {
            let offset = table + i * 40;
            image.bytes(offset, 40)?;
            let section = Section {
                rva: image.u32(offset + 12)?,
                size: image.u32(offset + 16)? as usize,
                raw: image.u32(offset + 20)? as usize,
                executable: image.u32(offset + 36)? & 0x20000000 != 0,
            };
            image.bytes(section.raw, section.size)?;
            ensure!(
                u64::from(section.rva) + section.size as u64 <= u64::from(u32::MAX) + 1,
                "Section RVA overflows"
            );
            image.sections.push(section);
        }
        let exception_rva = image.u32(optional + 136)?;
        let exception_size = image.u32(optional + 140)? as usize;
        ensure!(
            exception_size != 0 && exception_size.is_multiple_of(12),
            "Missing or invalid x64 function table"
        );
        let raw = image.raw(exception_rva, exception_size)?;
        for offset in (0..exception_size).step_by(12) {
            let begin = image.u32(raw + offset)?;
            let end = image.u32(raw + offset + 4)?;
            if begin != 0 && end > begin {
                image.starts.insert(begin);
            }
        }
        Ok(image)
    }

    fn bytes(&self, offset: usize, size: usize) -> Result<&[u8]> {
        let end = offset.checked_add(size).context("PE offset overflow")?;
        self.data.get(offset..end).context("Truncated PE image")
    }
    fn u16(&self, offset: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(offset, 2)?.try_into()?))
    }
    fn u32(&self, offset: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(offset, 4)?.try_into()?))
    }
    fn raw(&self, rva: u32, size: usize) -> Result<usize> {
        for section in &self.sections {
            if let Some(delta) = rva.checked_sub(section.rva) {
                let delta = delta as usize;
                if delta <= section.size && size <= section.size - delta {
                    return section.raw.checked_add(delta).context("PE offset overflow");
                }
            }
        }
        bail!("RVA is outside section data")
    }

    #[cfg(any(test, all(windows, target_arch = "x86_64")))]
    pub fn readable_data_rva(&self, rva: usize) -> bool {
        self.sections.iter().any(|s| {
            !s.executable
                && rva
                    .checked_sub(s.rva as usize)
                    .is_some_and(|offset| offset <= s.size && s.size - offset >= 8)
        })
    }

    #[cfg(any(test, all(windows, target_arch = "x86_64")))]
    pub fn require_exports(&self, required: &[&str]) -> Result<()> {
        ensure!(
            self.exports.0 != 0 && self.exports.1 >= 40,
            "Missing export directory"
        );
        let directory = self.raw(self.exports.0, 40)?;
        let function_count = self.u32(directory + 20)? as usize;
        let name_count = self.u32(directory + 24)? as usize;
        let names = self.raw(
            self.u32(directory + 32)?,
            name_count.checked_mul(4).context("Export count overflow")?,
        )?;
        let ordinals = self.raw(
            self.u32(directory + 36)?,
            name_count.checked_mul(2).context("Export count overflow")?,
        )?;
        let functions = self.raw(
            self.u32(directory + 28)?,
            function_count
                .checked_mul(4)
                .context("Export count overflow")?,
        )?;
        let mut exported = HashSet::new();
        for i in 0..name_count {
            let name_rva = self.u32(names + i * 4)?;
            let mut name = Vec::new();
            let mut terminated = false;
            for n in 0..1024 {
                let value = self.data
                    [self.raw(name_rva.checked_add(n).context("Export RVA overflow")?, 1)?];
                if value == 0 {
                    terminated = true;
                    break;
                }
                name.push(value);
            }
            ensure!(terminated, "Unterminated export name");
            let ordinal = self.u16(ordinals + i * 2)? as usize;
            ensure!(ordinal < function_count, "Invalid export ordinal");
            let target = self.u32(functions + ordinal * 4)?;
            if target != 0 {
                self.raw(target, 1)?;
                exported.insert(name);
            }
        }
        for &name in required {
            ensure!(exported.contains(name.as_bytes()), "Missing export: {name}");
            println!("  PASS export: {name}");
        }
        Ok(())
    }

    pub fn scan(&mut self) -> Result<bool> {
        self.methods.clear();
        let sets = self
            .signature_set()
            .map_or(SIGNATURE_SETS, std::slice::from_ref);
        let mut resolved = None;
        for set in sets {
            println!("Signature set: {}", set.build);
            let methods = self.scan_set(set)?;
            if methods.len() == set.methods.len() {
                if resolved.is_some() {
                    println!("Multiple signature sets resolved.");
                    return Ok(false);
                }
                resolved = Some(methods);
            }
        }
        if let Some(methods) = resolved {
            self.methods = methods;
            return Ok(true);
        }
        Ok(false)
    }

    fn scan_set(&self, set: &SignatureSet) -> Result<BTreeMap<&'static str, u32>> {
        let mut methods = BTreeMap::new();
        for &(name, text) in set.methods {
            let signature = pattern(text)?;
            let mut hits = Vec::new();
            for section in &self.sections {
                if !section.executable {
                    continue;
                }
                for (offset, bytes) in self
                    .bytes(section.raw, section.size)?
                    .windows(signature.len())
                    .enumerate()
                {
                    if matches(bytes, &signature) {
                        hits.push(section.rva + offset as u32);
                    }
                }
            }
            let valid = hits.len() == 1 && self.starts.contains(&hits[0]);
            print!("{name}: {} match(es)", hits.len());
            for rva in &hits {
                print!(" RVA=0x{rva:X}");
            }
            println!(
                " {}",
                if valid {
                    "[function boundary verified]"
                } else {
                    "[UNRESOLVED]"
                }
            );
            if valid {
                methods.insert(name, hits[0]);
            }
        }
        Ok(methods)
    }

    fn signature_set(&self) -> Option<&'static SignatureSet> {
        SIGNATURE_SETS.iter().find(|set| set.hash == self.hash)
    }

    #[cfg(any(test, all(windows, target_arch = "x86_64")))]
    pub fn method(&self, name: &str) -> Result<(u32, Vec<Option<u8>>)> {
        let rva = *self.methods.get(name).context("Unresolved method")?;
        let (_, text) = self
            .signature_set()
            .context("No reviewed signature set for this DLL")?
            .methods
            .iter()
            .find(|(method, _)| *method == name)
            .context("Unknown signature")?;
        Ok((rva, pattern(text)?))
    }

    pub fn verified(&self) -> bool {
        self.signature_set().is_some()
    }
    pub fn require_verified(&self) -> Result<()> {
        ensure!(
            self.verified(),
            "Runtime ABI not verified for this build. Use --scan-only; review the new DLL before enabling calls."
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture(methods: &[(&str, &str)]) -> Vec<u8> {
        let mut data = vec![0; 0x1600];
        put16(&mut data, 0, 0x5a4d);
        put32(&mut data, 0x3c, 0x80);
        put32(&mut data, 0x80, 0x4550);
        put16(&mut data, 0x84, 0x8664);
        put16(&mut data, 0x86, 2);
        put16(&mut data, 0x94, 240);
        put16(&mut data, 0x96, 0x2000);
        put16(&mut data, 0x98, 0x20b);
        put32(&mut data, 0x98 + 108, 16);
        put32(&mut data, 0x98 + 136, 0x2000);
        put32(&mut data, 0x98 + 140, 12 * methods.len() as u32);
        for (s, rva, raw, size, flags) in [
            (0x188, 0x1000, 0x200, 0x1000, 0x60000020),
            (0x1b0, 0x2000, 0x1200, 0x400, 0x40000040),
        ] {
            put32(&mut data, s + 12, rva);
            put32(&mut data, s + 16, size);
            put32(&mut data, s + 20, raw);
            put32(&mut data, s + 36, flags);
        }
        for (i, &(_, text)) in methods.iter().enumerate() {
            let signature = pattern(text).unwrap();
            for (j, byte) in signature.iter().enumerate() {
                data[0x200 + i * 256 + j] = byte.unwrap_or(0xcc);
            }
            put32(&mut data, 0x1200 + i * 12, 0x1000 + i as u32 * 256);
            put32(
                &mut data,
                0x1204 + i * 12,
                0x1000 + i as u32 * 256 + signature.len() as u32,
            );
        }
        data
    }
    #[test]
    fn resolves_only_unique_function_entries() {
        for set in SIGNATURE_SETS {
            let mut image = Image::parse(fixture(set.methods)).unwrap();
            assert!(image.scan().unwrap());
            assert!(image.scan().unwrap());
            assert_eq!(image.methods["SharePublic"], 0x1000);
            assert!(image.require_verified().is_err());
            assert!(image.method("SharePublic").is_err());
            image.starts.remove(&0x1000);
            assert!(!image.scan().unwrap());
            assert!(image.methods.is_empty());
            let mut data = fixture(set.methods);
            data.copy_within(0x200..0x300, 0x900);
            assert!(!Image::parse(data).unwrap().scan().unwrap());
        }
    }
    #[test]
    fn reviewed_hash_selects_the_matching_patterns_for_runtime() {
        for set in SIGNATURE_SETS {
            let mut image = Image::parse(fixture(set.methods)).unwrap();
            image.hash = set.hash.to_owned();
            image.require_verified().unwrap();
            assert!(image.scan().unwrap());
            for (index, &(name, text)) in set.methods.iter().enumerate() {
                let (rva, signature) = image.method(name).unwrap();
                assert_eq!(rva, 0x1000 + index as u32 * 256);
                assert_eq!(signature, pattern(text).unwrap());
            }
        }

        let mut image = Image::parse(fixture(WINDOWS_10)).unwrap();
        image.hash = SIGNATURE_SETS[0].hash.to_owned();
        assert!(!image.scan().unwrap());
        assert!(image.method("SharePublic").is_err());
    }
    #[test]
    fn rejects_methods_mixed_across_builds() {
        let mut methods = WINDOWS_10.to_vec();
        methods[0] = WINDOWS_11[0];
        let mut image = Image::parse(fixture(&methods)).unwrap();
        assert!(!image.scan().unwrap());
    }
    #[test]
    fn rejects_multiple_complete_sets_for_an_unknown_hash() {
        let mut methods = WINDOWS_11.to_vec();
        methods.extend(
            WINDOWS_10
                .iter()
                .copied()
                .filter(|entry| !WINDOWS_11.contains(entry)),
        );
        let mut image = Image::parse(fixture(&methods)).unwrap();
        assert!(!image.scan().unwrap());
        assert!(image.methods.is_empty());
    }
    #[test]
    fn rejects_truncation_architecture_and_bad_directories() {
        let data = fixture(WINDOWS_11);
        for n in 0..data.len() {
            assert!(Image::parse(data[..n].to_vec()).is_err(), "length={n}");
        }
        for (offset, value) in [
            (0x3c, u32::MAX),
            (0x84, 0x14c),
            (0x98 + 140, 13),
            (0x98 + 136, u32::MAX),
            (0x188 + 16, u32::MAX),
            (0x188 + 12, u32::MAX),
        ] {
            let mut data = fixture(WINDOWS_11);
            put32(&mut data, offset, value);
            assert!(Image::parse(data).is_err());
        }
    }
    #[test]
    fn bounds_and_wildcards() {
        let image = Image::parse(fixture(WINDOWS_11)).unwrap();
        assert!(image.readable_data_rva(0x2000));
        assert!(!image.readable_data_rva(0x23f9));
        assert!(!image.readable_data_rva(0x1000));
        assert!(image.raw(0x1fff, 2).is_err());
        assert!(matches(&[0x48, 0xab, 0xff], &pattern("48 ?? FF").unwrap()));
        assert!(!matches(&[0x48], &pattern("48 ?").unwrap()));
        assert!(pattern("GG").is_err());
    }
    #[test]
    fn validates_export_names_ordinals_and_targets() {
        let mut data = fixture(WINDOWS_11);
        put32(&mut data, 0x98 + 112, 0x2100);
        put32(&mut data, 0x98 + 116, 40);
        put32(&mut data, 0x1300 + 20, 1);
        put32(&mut data, 0x1300 + 24, 1);
        put32(&mut data, 0x1300 + 28, 0x2140);
        put32(&mut data, 0x1300 + 32, 0x2144);
        put32(&mut data, 0x1300 + 36, 0x2148);
        put32(&mut data, 0x1340, 0x1000);
        put32(&mut data, 0x1344, 0x2150);
        data[0x1350..0x1355].copy_from_slice(b"Test\0");
        let image = Image::parse(data.clone()).unwrap();
        assert!(image.require_exports(&["Test"]).is_ok());
        assert!(image.require_exports(&["Missing"]).is_err());
        put16(&mut data, 0x1348, 1);
        assert!(
            Image::parse(data.clone())
                .unwrap()
                .require_exports(&["Test"])
                .is_err()
        );
        put16(&mut data, 0x1348, 0);
        put32(&mut data, 0x1340, 0);
        assert!(
            Image::parse(data)
                .unwrap()
                .require_exports(&["Test"])
                .is_err()
        );
    }
}
