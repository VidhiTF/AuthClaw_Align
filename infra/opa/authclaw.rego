package authclaw

import rego.v1

# By default, allow is false
default allow = false
default reason = "Allowed"

# Allow the request if there are no deny reasons
allow if {
	count(deny_reasons) == 0
}

# Get the first deny reason if any exist
reason = r if {
	count(deny_reasons) > 0
	reasons_arr := [msg | deny_reasons[msg]]
	r := reasons_arr[0]
}

in_array(arr, item) if {
	arr[_] == item
}

# 1. Rate Limit Exceeded
deny_reasons["Rate limit exceeded"] if {
	input.rate_limit_exceeded == true
}

# 2. Model Blacklist
deny_reasons[msg] if {
	policy := input.policy
	in_array(policy.model_rules.blacklist, input.model)
	msg := sprintf("Model '%s' is blacklisted", [input.model])
}

# 3. Model Whitelist
deny_reasons[msg] if {
	policy := input.policy
	count(policy.model_rules.whitelist) > 0
	not in_array(policy.model_rules.whitelist, input.model)
	msg := sprintf("Model '%s' is not in whitelist", [input.model])
}

# 4. Regex block rules are also enforced by the gateway before provider egress.
# Keeping the OPA check here gives EvaluatePolicy the same YAML semantics and
# protects callers that use OPA directly for policy decisions.
deny_reasons[msg] if {
	policy := input.policy
	rule := policy.regex_rules[_]
	object.get(rule, "action", "redact") == "block"
	prompt := input.prompts[_]
	regex.match(rule.pattern, prompt)
	rule_name := object.get(rule, "name", "unnamed_rule")
	reason := object.get(rule, "reason", "Regex block")
	msg := sprintf("Policy rule %q action=block matched: %s", [rule_name, reason])
}

# 5. Topic classification blocking
deny_reasons[msg] if {
	policy := input.policy
	rule := policy.topic_rules[_]
	topic := input.topics[_]
	rule.topic == topic
	not in_array(rule.allowed_models, input.model)
	msg := sprintf("Topic block: %s", [rule.reason])
}
