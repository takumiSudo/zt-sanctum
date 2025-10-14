package mcp.authz
default allow := false
default reason := []

allow if {
  input.caller == "agent"
  input.tool == "echo"
  input.poca_verified == true
  input.schema_id == "echo.v1"
}

reason := ["not allowed"] if { not allow }