//! Wire-compatible execution-planning endpoint.

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::Value;

use crate::{pdf_edit::validate_operation_endpoint, user_spec::AgentSpec};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionStepResult {
    #[serde(alias = "step_index")]
    pub step_index: i64,
    #[serde(default, deserialize_with = "deserialize_optional_operation_endpoint")]
    pub tool: Option<String>,
    pub success: bool,
    #[serde(alias = "output_summary")]
    pub output_summary: Option<String>,
    #[serde(default, alias = "output_data")]
    pub output_data: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionContext {
    #[serde(alias = "trigger_type")]
    pub trigger_type: Option<String>,
    #[serde(default, alias = "input_files")]
    pub input_files: Vec<String>,
    #[serde(default)]
    pub metadata: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentExecutionRequest {
    #[serde(alias = "agent_spec")]
    pub agent_spec: AgentSpec,
    #[serde(alias = "current_step_index")]
    pub current_step_index: i64,
    #[serde(alias = "execution_context")]
    pub execution_context: ExecutionContext,
    #[serde(default, alias = "previous_step_results")]
    pub previous_step_results: Vec<ExecutionStepResult>,
}

fn deserialize_optional_operation_endpoint<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let endpoint = Option::<String>::deserialize(deserializer)?;
    if let Some(endpoint) = endpoint.as_deref() {
        validate_operation_endpoint(endpoint).map_err(de::Error::custom)?;
    }
    Ok(endpoint)
}

#[derive(Debug, Serialize)]
pub struct CannotContinueExecutionAction {
    outcome: &'static str,
    reason: String,
}

#[derive(Default)]
pub struct ExecutionPlanningAgent;

impl ExecutionPlanningAgent {
    #[must_use]
    pub fn next_action(request: &AgentExecutionRequest) -> CannotContinueExecutionAction {
        CannotContinueExecutionAction {
            outcome: "cannot_continue",
            reason: format!(
                "Execution planning is not implemented yet for step {}.",
                request.current_step_index
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AgentExecutionRequest, ExecutionPlanningAgent};

    #[test]
    fn next_action_preserves_the_python_stub_contract() -> Result<(), Box<dyn std::error::Error>> {
        let request: AgentExecutionRequest = serde_json::from_value(serde_json::json!({
            "agentSpec": {"name":"A","description":"B","objective":"C","steps":[{
                "kind":"tool","tool":"/api/v1/general/rotate-pdf","parameters":{"angle":90}
            }]},
            "currentStepIndex": 3,
            "executionContext": {"inputFiles":[],"metadata":{}},
            "previousStepResults":[{
                "stepIndex":0,"tool":"/api/v1/general/rotate-pdf","success":true
            }]
        }))?;
        let action = serde_json::to_value(ExecutionPlanningAgent::next_action(&request))?;
        assert_eq!(action["outcome"], "cannot_continue");
        assert_eq!(
            action["reason"],
            "Execution planning is not implemented yet for step 3."
        );
        Ok(())
    }

    #[test]
    fn execution_request_rejects_unknown_and_mismatched_saved_agent_steps() {
        for (tool, parameters) in [
            ("/api/v1/not-real", serde_json::json!({})),
            (
                "/api/v1/general/rotate-pdf",
                serde_json::json!({"flattenOnlyForms": false}),
            ),
        ] {
            let request = serde_json::from_value::<AgentExecutionRequest>(serde_json::json!({
                "agentSpec": {"name":"A","description":"B","objective":"C","steps":[{
                    "kind":"tool","tool":tool,"parameters":parameters
                }]},
                "currentStepIndex":0,
                "executionContext":{"inputFiles":[],"metadata":{}}
            }));
            assert!(request.is_err());
        }

        let request = serde_json::from_value::<AgentExecutionRequest>(serde_json::json!({
            "agentSpec":{"name":"A","description":"B","objective":"C","steps":[]},
            "currentStepIndex":1,
            "executionContext":{"inputFiles":[],"metadata":{}},
            "previousStepResults":[{
                "stepIndex":0,"tool":"/api/v1/not-real","success":false
            }]
        }));
        assert!(request.is_err());
    }
}
