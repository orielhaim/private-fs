use crate::{Error, Result};
use std::path::{Component, Path};

pub(crate) struct RelativePath<'a>(pub(crate) Vec<&'a std::ffi::OsStr>);
pub(crate) fn validate_component_spelling(path: &Path) -> Result<()> {
    let spelling = path.as_os_str().as_encoded_bytes();
    if spelling.contains(&0)
        || spelling
            .split(|b| *b == b'/' || *b == b'\\')
            .any(|c| c == b".." || c == b".")
    {
        return Err(Error::InvalidRelativePath);
    }
    Ok(())
}
impl<'a> RelativePath<'a> {
    pub(crate) fn new(path: &'a Path) -> Result<Self> {
        // Check the original spelling too: Path::components normalizes interior dots.
        validate_component_spelling(path)?;
        let spelling = path.as_os_str().as_encoded_bytes();
        if spelling.is_empty()
            || (cfg!(not(windows)) && spelling.contains(&b'\\'))
            || spelling.contains(&b':')
        {
            return Err(Error::InvalidRelativePath);
        }
        let parts: Option<Vec<_>> = path
            .components()
            .map(|c| match c {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        match parts {
            Some(parts) if !parts.is_empty() => Ok(Self(parts)),
            _ => Err(Error::InvalidRelativePath),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn invalid_paths() {
        for p in [
            "",
            "/x",
            "..",
            "a/../b",
            "./a",
            "a/./b",
            "C:foo",
            "C:\\foo",
            "\\\\host\\share",
            "a\0b",
        ] {
            assert!(RelativePath::new(Path::new(p)).is_err(), "{p:?}");
        }
    }
    proptest! {
        #[test]
        fn forbidden_components_cannot_be_hidden_by_separator_normalization(
            a in "[a-zA-Z0-9_-]{1,20}", b in "[a-zA-Z0-9_-]{1,20}",
            bad in prop::sample::select(vec![".", "..", "x:y", "x\0y"]),
            separators in prop::sample::select(vec!["/", "//", "\\", "\\\\", "/\\"]),
        ) {
            let spelling = format!("{a}{separators}{bad}{separators}{b}");
            prop_assert!(RelativePath::new(Path::new(&spelling)).is_err());
        }
        #[test]
        fn rooted_and_namespace_prefixed_paths_are_rejected(
            tail in "[a-zA-Z0-9_-]{1,40}",
            prefix in prop::sample::select(vec!["/", "//", "C:", "C:/", "\\\\host\\share\\", "\\\\?\\C:\\", "\\\\.\\", "\\\\?\\GLOBALROOT\\"]),
        ) {
            let spelling = format!("{prefix}{tail}");
            prop_assert!(RelativePath::new(Path::new(&spelling)).is_err());
        }
        #[test]
        fn accepted_paths_have_only_normal_components(s in ".*") {
            if let Ok(p) = RelativePath::new(Path::new(&s)) {
                prop_assert!(!p.0.is_empty());
                prop_assert!(Path::new(&s).components().all(|c| matches!(c, Component::Normal(_))));
                prop_assert!(!s.contains('\0'));
            }
        }
        #[test]
        fn traversal_is_rejected(a in "[a-z]{1,20}", b in "[a-z]{1,20}") {
            let path = format!("{a}/../{b}"); prop_assert!(RelativePath::new(Path::new(&path)).is_err());
        }
    }
}

#[cfg(all(test, unix))]
mod byte_tests {
    use super::*;
    use proptest::prelude::*;
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    proptest! {
        #[test]
        fn arbitrary_bytes_cannot_escape(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let path = Path::new(OsStr::from_bytes(&bytes));
            if let Ok(relative) = RelativePath::new(path) {
                prop_assert!(!bytes.contains(&0));
                prop_assert!(!bytes.contains(&b':'));
                prop_assert!(!bytes.contains(&b'\\'));
                prop_assert!(!path.is_absolute());
                for name in relative.0 {
                    prop_assert!(!name.as_bytes().contains(&b'/'));
                    prop_assert!(name != OsStr::new(".."));
                    prop_assert!(name != OsStr::new("."));
                }
            }
        }
        #[test]
        fn valid_nested_names_round_trip(parts in prop::collection::vec("[a-zA-Z0-9_-]{1,30}", 1..10)) {
            let spelling = parts.join("//");
            let path = Path::new(&spelling);
            let parsed = RelativePath::new(path).unwrap();
            prop_assert_eq!(parsed.0, parts.iter().map(OsStr::new).collect::<Vec<_>>());
        }
    }
}

#[cfg(all(test, windows))]
mod wide_tests {
    use super::*;
    use proptest::prelude::*;
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    proptest! {
        #[test]
        fn accepted_utf16_paths_never_escape(units in prop::collection::vec(any::<u16>(), 0..256)) {
            let name = OsString::from_wide(&units);
            let path = Path::new(&name);
            if let Ok(relative) = RelativePath::new(path) {
                prop_assert!(!units.contains(&0));
                prop_assert!(!units.contains(&(b':' as u16)));
                prop_assert!(!path.is_absolute());
                prop_assert!(!relative.0.is_empty());
                prop_assert!(path.components().all(|c| matches!(c, Component::Normal(_))));
            }
        }
        #[test]
        fn nested_windows_paths_keep_their_components(parts in prop::collection::vec("[a-zA-Z0-9_-]{1,30}", 1..10)) {
            let path = parts.join("\\");
            let parsed = RelativePath::new(Path::new(&path)).unwrap();
            prop_assert_eq!(parsed.0, parts.iter().map(std::ffi::OsStr::new).collect::<Vec<_>>());
        }
    }
}
