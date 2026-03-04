use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde_derive::Deserialize;

/// Represents the parsed contents of a `wasm-policy.yaml` file.
///
/// A wasm policy defines default access rules and per-package/interface/resource/function
/// overrides that control which host functions a WebAssembly component is allowed to use.
///
/// # Example YAML
///
/// ```yaml
/// default-mode: deny
///
/// packages:
///   wasi:io:
///     interfaces:
///       streams:
///         resources:
///           input-stream:
///             functions:
///               read:
///                 allow: true
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct WasmPolicy {
    /// The default mode for all functions not explicitly listed.
    /// `"allow"` means functions are allowed by default, `"deny"` means denied.
    pub default_mode: DefaultMode,

    /// Per-package policy overrides.
    #[serde(default)]
    pub packages: BTreeMap<String, PackagePolicy>,
}

/// The default access mode when no explicit rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultMode {
    Allow,
    Deny,
}

/// Policy for a specific package (e.g. `wasi:io`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct PackagePolicy {
    /// If set, overrides the default mode for all interfaces in this package.
    pub allow: Option<bool>,

    /// Per-interface policy overrides.
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfacePolicy>,
}

/// Policy for a specific interface (e.g. `streams`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfacePolicy {
    /// If set, overrides the default mode for all items in this interface.
    pub allow: Option<bool>,

    /// Per-resource policy overrides.
    #[serde(default)]
    pub resources: BTreeMap<String, ResourcePolicy>,

    /// Per-function policy overrides (for freestanding functions in the interface).
    #[serde(default)]
    pub functions: BTreeMap<String, FunctionPolicy>,
}

/// Policy for a specific resource (e.g. `input-stream`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResourcePolicy {
    /// If set, overrides the default mode for all functions in this resource.
    pub allow: Option<bool>,

    /// Per-function policy overrides within this resource.
    #[serde(default)]
    pub functions: BTreeMap<String, FunctionPolicy>,
}

/// Policy for a specific function (e.g. `read`).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FunctionPolicy {
    /// Whether this specific function is allowed.
    pub allow: bool,

    /// Optional constraints on function arguments.
    #[serde(default)]
    pub arguments: Vec<ArgumentConstraint>,
}

/// Constraint for a function argument.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArgumentConstraint {
    /// The type of the argument (e.g., "bool", "i32", "string").
    pub r#type: ArgumentType,

    /// The values to allow or block for this argument.
    #[serde(default)]
    pub values: Vec<ArgumentValue>,

    /// Whether the values field specifies allowed values (true) or blocked values (false).
    pub allow: bool,
}

/// Supported WIT primitive types for function arguments.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ArgumentType {
    /// Boolean value true or false.
    Bool,
    /// Signed 8-bit integer.
    S8,
    /// Signed 16-bit integer.
    S16,
    /// Signed 32-bit integer.
    S32,
    /// Signed 64-bit integer.
    S64,
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned 16-bit integer.
    U16,
    /// Unsigned 32-bit integer.
    U32,
    /// Unsigned 64-bit integer.
    U64,
    /// 32-bit floating-point number.
    F32,
    /// 64-bit floating-point number.
    F64,
    /// Unicode character (Unicode scalar value).
    Char,
    /// Unicode string.
    String,
}

/// Value that can be allowed or blocked for an argument constraint.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ArgumentValue {
    /// Boolean value.
    Bool(bool),
    /// Integer value (supports both signed and unsigned).
    Int(i64),
    /// Floating-point value.
    Float(f64),
    /// String value.
    String(String),
}

impl WasmPolicy {
    /// Determines whether a host function identified by package, interface, and
    /// function name is allowed to be called according to this policy.
    ///
    /// The resolution order (most specific wins):
    /// 1. Function-level `allow` within a resource (if `resource` is provided)
    /// 2. Resource-level `allow` (if `resource` is provided)
    /// 3. Function-level `allow` within an interface (freestanding functions)
    /// 4. Interface-level `allow`
    /// 5. Package-level `allow`
    /// 6. `default-mode`
    pub fn is_allowed(
        &self,
        package: &str,
        interface: &str,
        resource: Option<&str>,
        function_name: &str,
    ) -> bool {
        let default_allowed = match self.default_mode {
            DefaultMode::Allow => true,
            DefaultMode::Deny => false,
        };

        // Look up the package policy
        let Some(pkg) = self.packages.get(package) else {
            return default_allowed;
        };

        let pkg_allowed = pkg.allow.unwrap_or(default_allowed);

        // Look up the interface policy
        let Some(iface) = pkg.interfaces.get(interface) else {
            return pkg_allowed;
        };

        let iface_allowed = iface.allow.unwrap_or(pkg_allowed);

        if let Some(resource) = resource {
            if let Some(resource) = iface.resources.get(resource) {
                if let Some(func) = resource.functions.get(function_name) {
                    return func.allow;
                }
                return resource.allow.unwrap_or(iface_allowed);

            }
        }

        // Check freestanding functions in the interface
        if let Some(func) = iface.functions.get(function_name) {
            return func.allow;
        }

        iface_allowed
    }

    /// gives the per argument constraint
    pub fn get_argument_constraints(
        &self,
        package: &str,
        interface: &str,
        resource: Option<&str>,
        function_name: &str,
    ) -> Option<Vec<ArgumentConstraint>> {
        // Look up the package policy
        let iface = self.packages.get(package)?.interfaces.get(interface)?;

        if let Some(resource) = resource {
            Some(iface.resources.get(resource)?.functions.get(function_name)?.arguments.clone());
        }

        // Check freestanding functions in the interface
        Some(iface.functions.get(function_name)?.arguments.clone())
    }

    /// call this when no policy file is provided to get a default policy that allows everything
    /// this is needed to avoid having to check for the presence of a policy everywhere in the code
    pub fn new_no_file() -> Self {
        WasmPolicy {
            default_mode: DefaultMode::Allow,
            packages: BTreeMap::new(),
        }
    }
}
