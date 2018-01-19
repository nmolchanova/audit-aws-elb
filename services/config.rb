coreo_aws_rule "elb-old-ssl-policy" do
  action :define
  service :ElasticLoadBalancing
  link "http://kb.cloudcoreo.com/mydoc_elb-old-ssl-policy.html"
  display_name "ELB is using old SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is not the latest Amazon predefined SSL policy or is a custom ELB SSL policy."
  category "Security"
  suggested_action "Always use the current AWS predefined security policy."
  level "High"
  meta_nist_171_id "3.5.4"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "object.policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "=~"]
  raise_when     ["", /ELBSecurityPolicy-(?!2016-08)/]
  id_map "modifiers.load_balancer_name"
end

coreo_aws_rule_runner "advise-elb" do
  rules ${AUDIT_AWS_ELB_ALERT_LIST}
  service :ElasticLoadBalancing
  action :run
  regions ${AUDIT_AWS_ELB_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end