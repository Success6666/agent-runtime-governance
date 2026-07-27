package agents.tools

default allow := false

allow if {
  input.tool == "read_status"
}

allow if {
  input.tool in {"delete_file", "reconcile_unknown"}
  input.risk_tier == "HIGH"
  "admin" in input.permissions
}
