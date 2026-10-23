# Example OPA/Rego policy. Evaluate with:
#   skillfuse scan ./skills --rego examples/policy.rego
# The input document is the per-skill JSON from `skillfuse scan -f json` plus `signed` / `in_lock`.
package skillfuse

import rego.v1

default result := {"decision": "allow", "reasons": ["no rule matched"]}

deterministic_critical contains f if {
	some f in input.findings
	f.severity == "critical"
	f.confidence == "deterministic"
}

undeclared_write contains c if {
	some c in input.capabilities.undeclared
	c in {"shell.exec", "filesystem.write", "filesystem.delete", "network.egress"}
	not c in input.capabilities.weak
}

result := {"decision": "block", "reasons": reasons} if {
	count(deterministic_critical) > 0
	reasons := [sprintf("%s at %s:%d", [f.rule_id, f.location.path, f.location.line]) | some f in deterministic_critical]
}

result := {"decision": "quarantine", "reasons": reasons} if {
	count(deterministic_critical) == 0
	count(undeclared_write) > 0
	reasons := [sprintf("undeclared capability %s", [c]) | some c in undeclared_write]
}

result := {"decision": "quarantine", "reasons": ["unsigned skill with network egress"]} if {
	count(deterministic_critical) == 0
	count(undeclared_write) == 0
	input.signed == false
	"network.egress" in input.capabilities.inferred
}
