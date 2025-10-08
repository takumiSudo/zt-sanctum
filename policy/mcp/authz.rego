package mcp.authz

default allow := false
default reason := []

allow if {
  input.caller == "agent"
  input.tool == "echo"
}

reason := ["not allowed"] if {
  not allow
}