use anyhow::Result;
use anyhow::Context;
use serde::Deserialize;
use std::collections::HashMap;
use std::{fs, path::Path};

use crate::{WasiOptions, WasmOptions};

/// Parsed arguments from TOML policy file
#[derive(Deserialize, Debug)]
struct ParsedPolicyOptions {
    version: Option<String>,
    wasi: Option<WasiPolicyOptions>,
    entrypoint: Option<Vec<String>>,
    mount: HashMap<String, String>,
}

#[derive(Deserialize, Debug)]
struct WasiPolicyOptions {
    version: Option<String>,
    tls: Option<bool>,
    nn: Option<bool>,
    // nn_graph: Option<bool>,
    threads: Option<bool>,
    http: Option<bool>,
    tcp: Option<bool>,
    udp: Option<bool>,
    inherit_env: Option<bool>
}

#[derive(Default, Debug)]
pub struct PolicyOptions {
    pub wasi: WasiOptions,
    pub wasm: WasmOptions,
    pub entrypoint: Option<Vec<String>>,
    pub mounts: HashMap<String, String>,
}

impl PolicyOptions {

    pub fn new() -> Self {
        PolicyOptions {
            wasi: WasiOptions::default(),
            wasm: WasmOptions::default(),
            entrypoint: None,
            mounts: HashMap::new(),
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        let file_contents = fs::read_to_string(path_ref)
            .with_context(|| format!("failed to read config file: {path_ref:?}"))?;
        let options = toml::from_str::<ParsedPolicyOptions>(&file_contents)
            .with_context(|| format!("failed to parse config file: {path_ref:?}"))?;

        println!("{:?}", options);
        let mut policy = Self::new();

        if let Some(version) = options.version {
            match version.as_str() {
                "0.0.1" => {},
                _ => unimplemented!("This version is not supported yet.")
            }
        }
        if let Some(wasi_version) = options.wasi.as_ref().and_then(|w| w.version.clone()) {
            match wasi_version.as_str() {
                "preview_1" => policy.wasi.preview2 = Some(false),
                "preview_2" => policy.wasi.preview2 = Some(true),
                "preview_3" => policy.wasi.p3 = Some(true),
                _ => unimplemented!("This wasi version is not supported yet.")
            }
        }
        policy.wasi.tls = options.wasi.as_ref().and_then(|w| w.tls).or(Some(false));
        policy.wasi.nn = options.wasi.as_ref().and_then(|w| w.nn).or(Some(false));
        // policy.wasi.nn_graph = options.wasi.and_then(|w| w.nn_graph).or(Some(false));
        policy.wasi.threads = options.wasi.as_ref().and_then(|w| w.threads).or(Some(false));
        policy.wasi.http = options.wasi.as_ref().and_then(|w| w.http).or(Some(false));

        policy.mounts = options.mount;

        // todo!("add rest of options");
        Ok(policy)
    }
}