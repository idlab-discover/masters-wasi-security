use super::func::HostFuncMetadata;
use super::Val;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::fmt;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use wasmtime_environ::component::InterfaceType;

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
///                 arguments:
///                   - allow: false
///                     bool: [true]
///                   - allow: true
///                     s32: [10, 20, 30]
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WasmPolicy {
    /// The behaviour when a component does something not allowed by policy.
    #[serde(default, skip_serializing_if = "BehaviourOverwrite::is_none")]
    pub behaviour_overwrite: BehaviourOverwrite,

    /// The default mode for all functions not explicitly listed.
    /// `"allow"` means functions are allowed by default, `"deny"` means denied.
    pub default_mode: DefaultMode,

    /// Whether to run in create mode, collecting called functions.
    #[serde(skip)]
    pub create_mode: bool,

    /// How create mode should record function arguments.
    #[serde(skip)]
    pub create_args_mode: CreateArgsMode,

    /// Per-package policy overrides.
    #[serde(default)]
    pub packages: BTreeMap<String, PackagePolicy>,

    /// Collected complaints for this policy.
    #[serde(skip)]
    #[cfg(feature = "std")]
    pub complaints: std::sync::Arc<std::sync::Mutex<Vec<String>>>,

    /// Collected host functions that were called while running in create mode.
    #[serde(skip)]
    #[cfg(feature = "std")]
    pub called_functions: std::sync::Arc<std::sync::Mutex<BTreeSet<CalledHostFunction>>>,

    /// Collected argument constraints observed per called host function.
    #[serde(skip)]
    #[cfg(feature = "std")]
    pub called_arguments:
        std::sync::Arc<std::sync::Mutex<BTreeMap<CalledHostFunction, Vec<ArgumentConstraint>>>>,
}

/// A called host function, represented by package/interface/resource/function.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CalledHostFunction {
    pub package: String,
    pub interface: String,
    pub resource: Option<String>,
    pub function: String,
}

/// Controls how create mode records arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CreateArgsMode {
    /// Do not record arguments.
    #[default]
    None,
    /// Record all observed argument values.
    All,
    /// Record up to N unique values per argument, then switch to `no-constraint`.
    Max(usize),
}

/// The default access mode when no explicit rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultMode {
    Allow,
    Deny,
}

/// The behaviour when a component does something not allowed by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BehaviourOverwrite {
    #[default]
    None,
    Complain,
}

impl BehaviourOverwrite {
    fn is_none(&self) -> bool {
        matches!(self, BehaviourOverwrite::None)
    }
    pub fn is_complain(&self) -> bool {
        matches!(self, BehaviourOverwrite::Complain)
    }
}

/// Policy for a specific package (e.g. `wasi:io`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct PackagePolicy {
    /// If set, overrides the default mode for all interfaces in this package.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<bool>,

    /// Per-interface policy overrides.
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfacePolicy>,
}

/// Policy for a specific interface (e.g. `streams`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct InterfacePolicy {
    /// If set, overrides the default mode for all items in this interface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<bool>,

    /// Per-resource policy overrides.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourcePolicy>,

    /// Per-function policy overrides (for freestanding functions in the interface).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub functions: BTreeMap<String, FunctionPolicy>,
}

/// Policy for a specific resource (e.g. `input-stream`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ResourcePolicy {
    /// If set, overrides the default mode for all functions in this resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<bool>,

    /// Per-function policy overrides within this resource.
    #[serde(default)]
    pub functions: BTreeMap<String, FunctionPolicy>,
}

/// Policy for a specific function (e.g. `read`).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct FunctionPolicy {
    /// Whether this specific function is allowed.
    pub allow: bool,

    /// Optional constraints on function arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arguments: Vec<ArgumentConstraint>,
}

/// Constraint for a function argument.
///
/// Each constraint specifies a set of typed values and whether those values
/// are allowed or blocked. The type is encoded directly in the
/// [`ConstraintValues`] variant, which maps 1:1 to [`InterfaceType`]
/// primitives for easy matching.
///
/// # YAML format
///
/// Each constraint is a map with `allow` and exactly one type key whose
/// value is the list of constrained values:
///
/// ```yaml
/// - allow: false
///   bool: [true]
/// - allow: true
///   s32: [10, 20, 30]
/// ```
#[derive(Debug, Clone)]
pub enum ArgumentConstraint {
    /// An allow-list of constraint values. The argument must match one of these values.
    AllowList(ConstraintValues),
    /// A block-list of constraint values. The argument must not match any of these values.
    BlockList(ConstraintValues),
    /// No constraint is applied to this argument.
    NoConstraint,
}

/// Typed constraint values that directly correspond to WIT primitive types.
///
/// Each variant maps 1:1 to an [`InterfaceType`] primitive, so type
/// checking against a function signature is a simple discriminant comparison.
#[derive(Debug, Clone)]
pub enum ConstraintValues {
    Bool(Vec<bool>),
    S8(Vec<i8>),
    S16(Vec<i16>),
    S32(Vec<i32>),
    S64(Vec<i64>),
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    U64(Vec<u64>),
    Float32(Vec<f32>),
    Float64(Vec<f64>),
    Char(Vec<char>),
    String(Vec<String>),
}

impl Serialize for ArgumentConstraint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = match self {
            ArgumentConstraint::NoConstraint => serializer.serialize_map(Some(1))?,
            _ => serializer.serialize_map(Some(2))?,
        };

        match self {
            ArgumentConstraint::AllowList(values) => {
                map.serialize_entry("mode", "allow-list")?;
                serialize_constraint_values(values, &mut map)?;
            }
            ArgumentConstraint::BlockList(values) => {
                map.serialize_entry("mode", "block-list")?;
                serialize_constraint_values(values, &mut map)?;
            }
            ArgumentConstraint::NoConstraint => {
                map.serialize_entry("mode", "no-constraint")?;
            }
        }

        map.end()
    }
}

fn serialize_constraint_values<S>(
    values: &ConstraintValues,
    map: &mut S,
) -> Result<(), S::Error>
where
    S: SerializeMap,
{
    match values {
        ConstraintValues::Bool(v) => map.serialize_entry("bool", v),
        ConstraintValues::S8(v) => map.serialize_entry("s8", v),
        ConstraintValues::S16(v) => map.serialize_entry("s16", v),
        ConstraintValues::S32(v) => map.serialize_entry("s32", v),
        ConstraintValues::S64(v) => map.serialize_entry("s64", v),
        ConstraintValues::U8(v) => map.serialize_entry("u8", v),
        ConstraintValues::U16(v) => map.serialize_entry("u16", v),
        ConstraintValues::U32(v) => map.serialize_entry("u32", v),
        ConstraintValues::U64(v) => map.serialize_entry("u64", v),
        ConstraintValues::Float32(v) => map.serialize_entry("f32", v),
        ConstraintValues::Float64(v) => map.serialize_entry("f64", v),
        ConstraintValues::Char(v) => map.serialize_entry("char", v),
        ConstraintValues::String(v) => map.serialize_entry("string", v),
    }
}

impl ConstraintValues {
    /// Returns the [`InterfaceType`] that this constraint corresponds to.
    pub fn interface_type(&self) -> InterfaceType {
        match self {
            ConstraintValues::Bool(_) => InterfaceType::Bool,
            ConstraintValues::S8(_) => InterfaceType::S8,
            ConstraintValues::S16(_) => InterfaceType::S16,
            ConstraintValues::S32(_) => InterfaceType::S32,
            ConstraintValues::S64(_) => InterfaceType::S64,
            ConstraintValues::U8(_) => InterfaceType::U8,
            ConstraintValues::U16(_) => InterfaceType::U16,
            ConstraintValues::U32(_) => InterfaceType::U32,
            ConstraintValues::U64(_) => InterfaceType::U64,
            ConstraintValues::Float32(_) => InterfaceType::Float32,
            ConstraintValues::Float64(_) => InterfaceType::Float64,
            ConstraintValues::Char(_) => InterfaceType::Char,
            ConstraintValues::String(_) => InterfaceType::String,
        }
    }

    /// Check if this constraint's type matches the given [`InterfaceType`].
    pub fn matches_interface_type(&self, ty: InterfaceType) -> bool {
        self.interface_type() == ty
    }

    /// Returns `true` if the values list is empty (no specific values constrained).
    pub fn is_empty(&self) -> bool {
        match self {
            ConstraintValues::Bool(v) => v.is_empty(),
            ConstraintValues::S8(v) => v.is_empty(),
            ConstraintValues::S16(v) => v.is_empty(),
            ConstraintValues::S32(v) => v.is_empty(),
            ConstraintValues::S64(v) => v.is_empty(),
            ConstraintValues::U8(v) => v.is_empty(),
            ConstraintValues::U16(v) => v.is_empty(),
            ConstraintValues::U32(v) => v.is_empty(),
            ConstraintValues::U64(v) => v.is_empty(),
            ConstraintValues::Float32(v) => v.is_empty(),
            ConstraintValues::Float64(v) => v.is_empty(),
            ConstraintValues::Char(v) => v.is_empty(),
            ConstraintValues::String(v) => v.is_empty(),
        }
    }

    /// Returns `true` if the given [`Val`] is found in this constraint's value list.
    ///
    /// Returns `false` when the types don't match or the value is not present.
    pub fn contains_val(&self, val: &Val) -> bool {
        match (self, val) {
            (ConstraintValues::Bool(vs), Val::Bool(v)) => vs.contains(v),
            (ConstraintValues::S8(vs), Val::S8(v)) => vs.contains(v),
            (ConstraintValues::S16(vs), Val::S16(v)) => vs.contains(v),
            (ConstraintValues::S32(vs), Val::S32(v)) => vs.contains(v),
            (ConstraintValues::S64(vs), Val::S64(v)) => vs.contains(v),
            (ConstraintValues::U8(vs), Val::U8(v)) => vs.contains(v),
            (ConstraintValues::U16(vs), Val::U16(v)) => vs.contains(v),
            (ConstraintValues::U32(vs), Val::U32(v)) => vs.contains(v),
            (ConstraintValues::U64(vs), Val::U64(v)) => vs.contains(v),
            (ConstraintValues::Float32(vs), Val::Float32(v)) => {
                vs.iter().any(|c| c.to_bits() == v.to_bits())
            }
            (ConstraintValues::Float64(vs), Val::Float64(v)) => {
                vs.iter().any(|c| c.to_bits() == v.to_bits())
            }
            (ConstraintValues::Char(vs), Val::Char(v)) => vs.contains(v),
            (ConstraintValues::String(vs), Val::String(v)) => vs.iter().any(|c| c == v),
            _ => false,
        }
    }
}

impl ArgumentConstraint {
    /// Check whether `val` satisfies this constraint.
    pub fn check_val(&self, val: &Val) -> bool {
        match self {
            ArgumentConstraint::AllowList(values) => values.contains_val(val),
            ArgumentConstraint::BlockList(values) => !values.contains_val(val),
            ArgumentConstraint::NoConstraint => true,
        }
    }
}

fn push_unique_value<T: PartialEq>(values: &mut Vec<T>, value: T) -> bool {
    if !values.contains(&value) {
        values.push(value);
        true
    } else {
        false
    }
}

impl ConstraintValues {
    fn len(&self) -> usize {
        match self {
            ConstraintValues::Bool(v) => v.len(),
            ConstraintValues::S8(v) => v.len(),
            ConstraintValues::S16(v) => v.len(),
            ConstraintValues::S32(v) => v.len(),
            ConstraintValues::S64(v) => v.len(),
            ConstraintValues::U8(v) => v.len(),
            ConstraintValues::U16(v) => v.len(),
            ConstraintValues::U32(v) => v.len(),
            ConstraintValues::U64(v) => v.len(),
            ConstraintValues::Float32(v) => v.len(),
            ConstraintValues::Float64(v) => v.len(),
            ConstraintValues::Char(v) => v.len(),
            ConstraintValues::String(v) => v.len(),
        }
    }

    fn push_unique(&mut self, val: &Val) -> bool {
        match (self, val) {
            (ConstraintValues::Bool(vs), Val::Bool(v)) => push_unique_value(vs, *v),
            (ConstraintValues::S8(vs), Val::S8(v)) => push_unique_value(vs, *v),
            (ConstraintValues::S16(vs), Val::S16(v)) => push_unique_value(vs, *v),
            (ConstraintValues::S32(vs), Val::S32(v)) => push_unique_value(vs, *v),
            (ConstraintValues::S64(vs), Val::S64(v)) => push_unique_value(vs, *v),
            (ConstraintValues::U8(vs), Val::U8(v)) => push_unique_value(vs, *v),
            (ConstraintValues::U16(vs), Val::U16(v)) => push_unique_value(vs, *v),
            (ConstraintValues::U32(vs), Val::U32(v)) => push_unique_value(vs, *v),
            (ConstraintValues::U64(vs), Val::U64(v)) => push_unique_value(vs, *v),
            (ConstraintValues::Float32(vs), Val::Float32(v)) => {
                if !vs.iter().any(|c| c.to_bits() == v.to_bits()) { vs.push(*v); true } else { false }
            }
            (ConstraintValues::Float64(vs), Val::Float64(v)) => {
                if !vs.iter().any(|c| c.to_bits() == v.to_bits()) { vs.push(*v); true } else { false }
            }
            (ConstraintValues::Char(vs), Val::Char(v)) => push_unique_value(vs, *v),
            (ConstraintValues::String(vs), Val::String(v)) => push_unique_value(vs, v.clone()),
            _ => false,
        }
    }
}

fn constraint_values_from_val(val: &Val) -> Option<ConstraintValues> {
    Some(match val {
        Val::Bool(v) => ConstraintValues::Bool(vec![*v]),
        Val::S8(v) => ConstraintValues::S8(vec![*v]),
        Val::S16(v) => ConstraintValues::S16(vec![*v]),
        Val::S32(v) => ConstraintValues::S32(vec![*v]),
        Val::S64(v) => ConstraintValues::S64(vec![*v]),
        Val::U8(v) => ConstraintValues::U8(vec![*v]),
        Val::U16(v) => ConstraintValues::U16(vec![*v]),
        Val::U32(v) => ConstraintValues::U32(vec![*v]),
        Val::U64(v) => ConstraintValues::U64(vec![*v]),
        Val::Float32(v) => ConstraintValues::Float32(vec![*v]),
        Val::Float64(v) => ConstraintValues::Float64(vec![*v]),
        Val::Char(v) => ConstraintValues::Char(vec![*v]),
        Val::String(v) => ConstraintValues::String(vec![v.clone()]),
        _ => return None,
    })
}

fn max_values_limit(mode: CreateArgsMode) -> Option<usize> {
    match mode {
        CreateArgsMode::None => Some(0),
        CreateArgsMode::All => None,
        CreateArgsMode::Max(n) => Some(n),
    }
}

/// All valid fields in an argument constraint map.
const CONSTRAINT_FIELDS: &[&str] = &[
    "mode", "bool", "s8", "s16", "s32", "s64", "u8", "u16", "u32", "u64", "f32", "f64", "char",
    "string",
];

fn values_check<'de, M, T, R>(
    values: &mut Option<R>,
    f: fn(T) -> R,
    map: &mut M,
) -> Result<(), M::Error>
where
    M: MapAccess<'de>,
    T: Deserialize<'de>,
{
    if values.is_some() {
        return Err(de::Error::custom(
            "multiple type keys found; expected exactly one",
        ));
    }
    *values = Some(f(map.next_value()?));
    Ok(())
}

impl<'de> Deserialize<'de> for ArgumentConstraint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ArgumentConstraintVisitor;

        impl<'de> Visitor<'de> for ArgumentConstraintVisitor {
            type Value = ArgumentConstraint;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    f,
                    "a map with 'mode' and optionally one type key ({})",
                    CONSTRAINT_FIELDS[1..].join(", ")
                )
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut mode: Option<String> = None;
                let mut values: Option<ConstraintValues> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "mode" => {
                            if mode.is_some() {
                                return Err(de::Error::duplicate_field("mode"));
                            }
                            mode = Some(map.next_value()?);
                        }
                        "bool" => values_check(&mut values, ConstraintValues::Bool, &mut map)?,
                        "s8" => values_check(&mut values, ConstraintValues::S8, &mut map)?,
                        "s16" => values_check(&mut values, ConstraintValues::S16, &mut map)?,
                        "s32" => values_check(&mut values, ConstraintValues::S32, &mut map)?,
                        "s64" => values_check(&mut values, ConstraintValues::S64, &mut map)?,
                        "u8" => values_check(&mut values, ConstraintValues::U8, &mut map)?,
                        "u16" => values_check(&mut values, ConstraintValues::U16, &mut map)?,
                        "u32" => values_check(&mut values, ConstraintValues::U32, &mut map)?,
                        "u64" => values_check(&mut values, ConstraintValues::U64, &mut map)?,
                        "f32" => values_check(&mut values, ConstraintValues::Float32, &mut map)?,
                        "f64" => values_check(&mut values, ConstraintValues::Float64, &mut map)?,
                        "char" => values_check(&mut values, ConstraintValues::Char, &mut map)?,
                        "string" => values_check(&mut values, ConstraintValues::String, &mut map)?,
                        other => {
                            return Err(de::Error::unknown_field(other, CONSTRAINT_FIELDS));
                        }
                    }
                }

                let mode = mode.ok_or_else(|| de::Error::missing_field("mode"))?;
                match mode.as_str() {
                    "allow-list" | "block-list" => {
                        let values = values.ok_or_else(|| {
                            de::Error::custom(format!(
                                "missing type key for {mode}; expected exactly one of: {}",
                                CONSTRAINT_FIELDS[1..].join(", ")
                            ))
                        })?;
                        if mode == "allow-list" {
                            Ok(ArgumentConstraint::AllowList(values))
                        } else {
                            Ok(ArgumentConstraint::BlockList(values))
                        }
                    }
                    "no-constraint" => {
                        if values.is_some() {
                            return Err(de::Error::custom(
                                "no-constraint mode does not take a type key",
                            ));
                        }
                        Ok(ArgumentConstraint::NoConstraint)
                    }
                    _ => Err(de::Error::custom(
                        "invalid mode; expected allow-list, block-list, or no-constraint",
                    )),
                }
            }
        }

        deserializer.deserialize_map(ArgumentConstraintVisitor)
    }
}

impl WasmPolicy {
    #[cfg(feature = "std")]
    pub(crate) fn should_record_arguments(&self) -> bool {
        self.create_mode && self.create_args_mode != CreateArgsMode::None
    }

    #[cfg(feature = "std")]
    pub(crate) fn record_function_call(
        &self,
        metadata: &HostFuncMetadata,
    ) {
        if !self.create_mode {
            return;
        }

        if let Ok(mut called) = self.called_functions.lock() {
            called.insert(CalledHostFunction {
                package: metadata.package.to_string(),
                interface: metadata.interface.to_string(),
                resource: metadata.resource.as_deref().map(|s| s.to_string()),
                function: metadata.name.to_string(),
            });
        }
    }

    #[cfg(feature = "std")]
    pub(crate) fn record_function_arguments(
        &self,
        metadata: &HostFuncMetadata,
        arguments: &[Val],
    ) {
        if !self.should_record_arguments() {
            return;
        }

        let max_values = max_values_limit(self.create_args_mode);
        let key = CalledHostFunction {
            package: metadata.package.to_string(),
            interface: metadata.interface.to_string(),
            resource: metadata.resource.as_deref().map(|s| s.to_string()),
            function: metadata.name.to_string(),
        };

        let Ok(mut map) = self.called_arguments.lock() else {
            return;
        };
        let entry = map.entry(key).or_default();
        if entry.len() < arguments.len() {
            entry.resize(arguments.len(), ArgumentConstraint::NoConstraint);
        }

        for (i, arg) in arguments.iter().enumerate() {
            let Some(initial_values) = constraint_values_from_val(arg) else {
                entry[i] = ArgumentConstraint::NoConstraint;
                continue;
            };

            match &mut entry[i] {
                ArgumentConstraint::NoConstraint => {
                    if max_values == Some(0) {
                        continue;
                    }
                    entry[i] = ArgumentConstraint::AllowList(initial_values);
                }
                ArgumentConstraint::AllowList(values) => {
                    if !values.push_unique(arg) {
                        entry[i] = ArgumentConstraint::NoConstraint;
                        continue;
                    }
                    if let Some(limit) = max_values {
                        if values.len() > limit {
                            entry[i] = ArgumentConstraint::NoConstraint;
                        }
                    }
                }
                ArgumentConstraint::BlockList(_) => {
                    entry[i] = ArgumentConstraint::NoConstraint;
                }
            }
        }
    }

    /// Renders the recorded calls as a YAML policy file for create mode.
    #[cfg(feature = "std")]
    pub fn create_policy_yaml(&self) -> Option<String> {
        if !self.create_mode {
            return None;
        }

        let called_functions = self.called_functions.lock().ok()?;
        let called_arguments = self.called_arguments.lock().ok()?;
        let mut packages: BTreeMap<String, PackagePolicy> = BTreeMap::new();

        for called in called_functions.iter() {
            let package = packages.entry(called.package.clone()).or_default();
            let interface = package
                .interfaces
                .entry(called.interface.clone())
                .or_default();
            let mut function_policy = FunctionPolicy {
                allow: true,
                arguments: Vec::new(),
            };

            if let Some(args) = called_arguments.get(called) {
                function_policy.arguments = args.clone();
            }

            if let Some(resource) = &called.resource {
                interface
                    .resources
                    .entry(resource.clone())
                    .or_default()
                    .functions
                    .insert(called.function.clone(), function_policy);
            } else {
                interface
                    .functions
                    .insert(called.function.clone(), function_policy);
            }
        }

        serde_yaml::to_string(&WasmPolicy {
            behaviour_overwrite: BehaviourOverwrite::default(),
            default_mode: DefaultMode::Deny,
            create_mode: false,
            create_args_mode: CreateArgsMode::None,
            packages,
            #[cfg(feature = "std")]
            complaints: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            #[cfg(feature = "std")]
            called_functions: std::sync::Arc::new(std::sync::Mutex::new(BTreeSet::new())),
            #[cfg(feature = "std")]
            called_arguments: std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        })
        .ok()
    }

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
    ) -> (bool, Vec<ArgumentConstraint>) {
        let default_allowed = match self.default_mode {
            DefaultMode::Allow => true,
            DefaultMode::Deny => false,
        };

        // Look up the package policy
        let Some(pkg) = self.packages.get(package) else {
            return (default_allowed, Vec::new());
        };

        let pkg_allowed = pkg.allow.unwrap_or(default_allowed);

        // Look up the interface policy
        let Some(iface) = pkg.interfaces.get(interface) else {
            return (pkg_allowed, Vec::new());
        };

        let iface_allowed = iface.allow.unwrap_or(pkg_allowed);

        if let Some(resource) = resource {
            if let Some(resource) = iface.resources.get(resource) {
                if let Some(func) = resource.functions.get(function_name) {
                    return (func.allow, func.arguments.clone());
                }
                return (resource.allow.unwrap_or(iface_allowed), Vec::new());
            }
        } else if let Some(func) = iface.functions.get(function_name) {
            // Check freestanding functions in the interface
            return (func.allow, func.arguments.clone());
        }

        (iface_allowed, Vec::new())
    }

    /// call this when no policy file is provided to get a default policy that allows everything
    /// this is needed to avoid having to check for the presence of a policy everywhere in the code
    pub fn new_no_file() -> Self {
        WasmPolicy {
            behaviour_overwrite: BehaviourOverwrite::default(),
            default_mode: DefaultMode::Allow,
            create_mode: false,
            create_args_mode: CreateArgsMode::None,
            packages: BTreeMap::new(),
            #[cfg(feature = "std")]
            complaints: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            #[cfg(feature = "std")]
            called_functions: std::sync::Arc::new(std::sync::Mutex::new(BTreeSet::new())),
            #[cfg(feature = "std")]
            called_arguments: std::sync::Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }
}
