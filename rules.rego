package component.host_function

import rego.v1

default allow := false

# The final decision: authorized by the hierarchy AND arguments pass constraints
allow  if {
    is_authorized
    args_valid
}

# 1. Evaluate Hierarchy (Most specific to least specific)
# Using `else` ensures we stop at the deepest explicitly defined `allow` flag.
is_authorized := d if {
    d := func_config.allow
} else := d if {
    d := res_config.allow
} else := d if {
    d := intf_config.allow
} else := d if {
    d := pkg_config.allow
} else := d if {
    d := data["default-mode"] == "allow"
}

# 2. Safe Data Lookups
pkg_config := data.packages[input.pkg]
intf_config := pkg_config.interfaces[input.intf]

# Resolve resource and function configurations conditionally, depending on whether 
# the input specifies a "resource" context.
res_config := intf_config.resources[input.res] if {
    "res" in object.keys(input)
}

func_config := res_config.functions[input.fn] if {
    "res" in object.keys(input)
} else := intf_config.functions[input.fn]


# 3. Argument Constraints Validation
default args_valid := false

args_valid if {
    not func_config.arguments
}

args_valid if {
    not input.args
}

args_valid if {
    func_config.arguments
    not has_arg_violation
}

# Violation: block-list contains the provided argument
has_arg_violation if {
    some i, constraint in func_config.arguments
    arg_val := input.args[i]
    
    constraint.mode == "block-list"
    
    # Dynamically find the type key (e.g., 'bool', 's32') by ignoring the 'mode' key
    some type_key, blocked_values in constraint
    type_key != "mode"
    arg_val in blocked_values
}

# Violation: allow-list does NOT contain the provided argument
has_arg_violation if {
    some i, constraint in func_config.arguments
    arg_val := input.args[i]
    
    constraint.mode == "allow-list"
    
    some type_key, allowed_values in constraint
    type_key != "mode"
    not arg_val in allowed_values
}