/// Invalid IO Pattern.
///
/// This error signals that a wrong IO Pattern has been declared
/// upon instantiation of the SAFE sponge.
#[derive(Debug, Clone)]
pub struct InvalidTag(String);

impl From<&str> for InvalidTag {
    fn from(s: &str) -> Self {
        s.to_string().into()
    }
}

impl From<String> for InvalidTag {
    fn from(s: String) -> Self {
        Self(s)
    }
}
