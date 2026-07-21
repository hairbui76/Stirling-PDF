//! Wire-compatible execution-planning endpoint.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::user_spec::AgentSpec;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionStepResult {
    #[serde(alias = "step_index")]
    pub step_index: i64,
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
            "agentSpec": {"name":"A","description":"B","objective":"C","steps":[]},
            "currentStepIndex": 3,
            "executionContext": {"inputFiles":[],"metadata":{}}
        }))?;
        let action = serde_json::to_value(ExecutionPlanningAgent::next_action(&request))?;
        assert_eq!(action["outcome"], "cannot_continue");
        assert_eq!(
            action["reason"],
            "Execution planning is not implemented yet for step 3."
        );
        Ok(())
    }
}
