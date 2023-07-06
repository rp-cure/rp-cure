use bcder::{Oid, ConstOid};
use dirs;

pub static BASE_DATA_DIR: &str = "data/";
pub static BASE_REPO_DIR: &str = "data/repo/";
pub static BASE_RRDP_DIR: &str = "data/rrdp/";
pub static BASE_KEY_DIR: &str = "data/keys/";
pub static TAL_DIR: &str = "data/tals/";

pub static DOMAIN: &str = "my.server.com";

pub static DEFAULT_TA_NAME: &str = "ta";
pub static DEFAULT_CA_NAME: &str = "newca";

pub static ROUTINATOR_TAL_DIR: &str = ".rpki-cache/tals/";

pub static DEFAULT_IPSPACE_FIRST_OCTET: u16 = 10;
pub static DEFAULT_IPSPACE_SEC_OCTET: u16 = 0;
pub static DEFAULT_IPSPACE_PREFIX: u16 = 16;

pub static DEFAULT_AS_RESOURCES_MIN: u32 = 0;
pub static DEFAULT_AS_RESOURCES_MAX: u32 = 10000;

pub static SSL_KEY_WEBSERVER: &str = "git/rpki-fuzzing/certs/certs.pem";

// Rust does not allow for Vectors as static variables so we seperate the strings by comma and split later
pub static TRAVERSAL_STRINGS: &str = ",../,%2e%2e%2f,%2e%2e/,..%2f,%2e%2e%5c,%2e%2e\\,..%5c,%252e%252e%255c,..%255c,..%c0%af,..%c1%9c,.\\./,..\\,.*./,.\0./,.\t./,.\n./,.\r\n./,.../,..../";
pub const GBR: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 35]);
