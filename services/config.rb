
coreo_aws_rule "elb-inventory" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "ELB Object Inventory"
  description "This rule performs an inventory on all Classic ELB's in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.load_balancer_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.load_balancer_descriptions.load_balancer_name"
end

coreo_aws_rule "elb-old-ssl-policy" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-old-ssl-policy.html"
  display_name "ELB is using old SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is not the latest Amazon predefined SSL policy or is a custom ELB SSL policy."
  category "Security"
  suggested_action "Always use the current AWS predefined security policy."
  level "Critical"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "!~"]
  raise_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end

coreo_aws_rule "elb-current-ssl-policy" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-current-ssl-policy.html"
  include_violations_in_count false
  display_name "ELB is using current SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is the latest Amazon predefined SSL policy"
  category "Informational"
  suggested_action "None."
  level "Informational"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "=~"]
  raise_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
  id_map "modifiers.load_balancer_name"
end

coreo_uni_util_variables "elb-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.number_violations' => 'unset'}
            ])
end

coreo_aws_rule_runner_elb "advise-elb" do
  rules ${AUDIT_AWS_ELB_ALERT_LIST}
  action :run
  regions ${AUDIT_AWS_ELB_REGIONS}
end

coreo_uni_util_variables "elb-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report'},
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.number_violations'},

            ])
end

coreo_uni_util_jsrunner "elb-tags-to-notifiers-array" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.9.6"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report}'
  function <<-EOH
  
function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');

  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    console.log("error loading table YAML");
    table = {};

  }
  try {
    suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    console.log("error loading suppression YAML");
    suppression = {};
  }

  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  let alertListToJSON = "${AUDIT_AWS_ELB_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}

setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_ELB_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_ELB_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_ELB_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_ELB_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const VARIABLES = { NO_OWNER_EMAIL, OWNER_TAG,
     ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditELB = new CloudCoreoJSRunner(JSON_INPUT, VARIABLES);
const letters = AuditELB.getLetters();

const newJSONInput = AuditELB.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(newJSONInput));
coreoExport('report', JSON.stringify(newJSONInput['violations']));

callback(letters);
  EOH
end

coreo_uni_util_variables "elb-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.JSONReport'},{'COMPOSITE::coreo_aws_rule_runner_elb.advise-elb.report' => 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.report'},
                {'COMPOSITE::coreo_uni_util_variables.elb-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.table'}
            ])
end

coreo_uni_util_jsrunner "elb-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}

let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-elb-to-tag-values" do
  action((("${AUDIT_AWS_ELB_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.elb-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-elb-rollup" do
  action((("${AUDIT_AWS_ELB_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_ELB_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.elb-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb rule results on PLAN::stack_name :: PLAN::name'
  })
end


