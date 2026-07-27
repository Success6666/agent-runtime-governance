package agents.tools

default allow := false

allow if {
  input.tool == "read_status"
}

allow if {
  input.tool == "delete_file"
  input.risk_tier == "HIGH"
  "admin" in input.permissions
}

allow if {
  input.tool == "reconcile_unknown"
  input.risk_tier == "HIGH"
  "admin" in input.permissions
}
