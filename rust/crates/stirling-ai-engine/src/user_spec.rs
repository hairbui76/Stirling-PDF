//! Drafting and revision of saved agent specifications.

use std::{fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::{Value, json};
use tokio::time::timeout;

use crate::{
    orchestrator::OrchestratorRequest,
    pdf_edit::{
        PdfEditAgent, PdfEditError, catalogued_operations, validate_operation_parameters,
        validate_processing_endpoint,
    },
    pdf_question::ConversationMessage,
    structured_output::{ModelError, StructuredOutputModel, ToolDefinition},
};

const USER_SPEC_TOOL: &str = "write_user_agent_spec_metadata";
const USER_SPEC_PROMPT: &str = "Create or revise a saved agent draft from the provided request and edit plan. Return a concise name, description, and objective. Keep the workflow grounded and practical.";

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentSpecStep {
    Tool {
        tool: String,
        parameters: Value,
    },
    AiTool {
        title: String,
        description: String,
        tool: String,
        instruction: String,
    },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum UnvalidatedAgentSpecStep {
    Tool {
        tool: String,
        parameters: Value,
    },
    AiTool {
        title: String,
        description: String,
        tool: String,
        instruction: String,
    },
}

impl<'de> Deserialize<'de> for AgentSpecStep {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match UnvalidatedAgentSpecStep::deserialize(deserializer)? {
            UnvalidatedAgentSpecStep::Tool { tool, parameters } => {
                let parameters =
                    validate_operation_parameters(&tool, &parameters).map_err(de::Error::custom)?;
                Ok(Self::Tool { tool, parameters })
            }
            UnvalidatedAgentSpecStep::AiTool {
                title,
                description,
                tool,
                instruction,
            } => {
                validate_processing_endpoint(&tool).map_err(de::Error::custom)?;
                Ok(Self::AiTool {
                    title,
                    description,
                    tool,
                    instruction,
                })
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDraft {
    pub name: String,
    pub description: String,
    pub objective: String,
    #[serde(default)]
    pub steps: Vec<AgentSpecStep>,
}

pub type AgentSpec = AgentDraft;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentDraftRequest {
    #[serde(alias = "user_message")]
    pub user_message: String,
    #[serde(default, alias = "conversation_history")]
    pub conversation_history: Vec<ConversationMessage>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentRevisionRequest {
    #[serde(alias = "user_message")]
    pub user_message: String,
    #[serde(default, alias = "conversation_history")]
    pub conversation_history: Vec<ConversationMessage>,
    #[serde(alias = "current_draft")]
    pub current_draft: AgentDraft,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EditPlan {
    outcome: String,
    summary: String,
    rationale: Option<String>,
    steps: Vec<AgentSpecStep>,
    resume_with: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserSpecMetadata {
    name: String,
    description: String,
    objective: String,
}

#[derive(Clone, Debug)]
pub enum UserSpecError {
    ModelUnavailable(String),
    Model(String),
    Edit(String),
    Catalog(String),
}

impl fmt::Display for UserSpecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ModelUnavailable(message)
            | Self::Model(message)
            | Self::Edit(message)
            | Self::Catalog(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for UserSpecError {}

impl From<PdfEditError> for UserSpecError {
    fn from(error: PdfEditError) -> Self {
        match error {
            PdfEditError::ModelUnavailable(message) => Self::ModelUnavailable(message),
            PdfEditError::Model(message) => Self::Edit(message),
            PdfEditError::Catalog(message) => Self::Catalog(message),
        }
    }
}

pub struct UserSpecAgent {
    model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
    pdf_edit: PdfEditAgent,
    max_output_tokens: u32,
    worker_timeout: Duration,
}

impl UserSpecAgent {
    #[must_use]
    pub fn new(
        model: Result<Arc<dyn StructuredOutputModel>, ModelError>,
        pdf_edit: PdfEditAgent,
        max_output_tokens: u32,
        worker_timeout: Duration,
    ) -> Self {
        Self {
            model,
            pdf_edit,
            max_output_tokens,
            worker_timeout,
        }
    }

    /// Drafts a user agent. `None` means a direct draft API call and uses the
    /// complete catalog; `Some` is the authoritative server-enabled endpoint set.
    ///
    /// # Errors
    ///
    /// Returns an error when catalog loading, edit planning, or metadata generation fails.
    pub async fn draft(
        &self,
        request: &AgentDraftRequest,
        enabled_endpoints: Option<&[String]>,
    ) -> Result<Value, UserSpecError> {
        let edit_plan = self
            .build_edit_plan(
                &request.user_message,
                &request.conversation_history,
                enabled_endpoints,
            )
            .await?;
        let Some(edit_plan) = parse_plan_or_terminal(&edit_plan)? else {
            return Ok(edit_plan);
        };
        let prompt = draft_prompt(request, &edit_plan)?;
        let metadata = self.metadata(&prompt).await?;
        Ok(draft_response(metadata, edit_plan.steps))
    }

    /// Revises a user agent, replacing deterministic tool steps while keeping
    /// existing AI-tool steps as in the Python workflow.
    ///
    /// # Errors
    ///
    /// Returns an error when edit planning, serialization, or metadata generation fails.
    pub async fn revise(&self, request: &AgentRevisionRequest) -> Result<Value, UserSpecError> {
        let planning_request = format!(
            "Current objective: {}\nRevision request: {}",
            request.current_draft.objective, request.user_message
        );
        let edit_plan = self
            .build_edit_plan(&planning_request, &request.conversation_history, None)
            .await?;
        let Some(edit_plan) = parse_plan_or_terminal(&edit_plan)? else {
            return Ok(edit_plan);
        };
        let prompt = revision_prompt(request, &edit_plan)?;
        let metadata = self.metadata(&prompt).await?;
        let mut steps = edit_plan.steps;
        steps.extend(
            request
                .current_draft
                .steps
                .iter()
                .filter(|step| matches!(step, AgentSpecStep::AiTool { .. }))
                .cloned(),
        );
        Ok(draft_response(metadata, steps))
    }

    pub(crate) async fn orchestrate(
        &self,
        request: &OrchestratorRequest,
    ) -> Result<Value, UserSpecError> {
        self.draft(
            &AgentDraftRequest {
                user_message: request.user_message.clone(),
                conversation_history: request.conversation_history.clone(),
            },
            Some(&request.enabled_endpoints),
        )
        .await
    }

    async fn build_edit_plan(
        &self,
        user_message: &str,
        conversation_history: &[ConversationMessage],
        enabled_endpoints: Option<&[String]>,
    ) -> Result<Value, UserSpecError> {
        let enabled_endpoints = match enabled_endpoints {
            Some(endpoints) => endpoints.to_vec(),
            None => catalogued_operations()?,
        };
        let request = OrchestratorRequest::for_user_spec(
            user_message.to_owned(),
            conversation_history.to_vec(),
            enabled_endpoints,
        );
        self.pdf_edit
            .handle_terminal(&request)
            .await
            .map_err(UserSpecError::from)
    }

    async fn metadata(&self, prompt: &str) -> Result<UserSpecMetadata, UserSpecError> {
        let model = self
            .model
            .as_ref()
            .map_err(|error| UserSpecError::ModelUnavailable(error.to_string()))?;
        let schema = metadata_schema();
        let future = model.complete(
            USER_SPEC_PROMPT,
            prompt,
            self.max_output_tokens,
            ToolDefinition {
                name: USER_SPEC_TOOL,
                description: "Write concise metadata for a saved user agent specification.",
                input_schema: &schema,
            },
        );
        let value = timeout(self.worker_timeout, future)
            .await
            .map_err(|_| UserSpecError::Model(format!("{USER_SPEC_TOOL} timed out")))?
            .map_err(|error| UserSpecError::Model(error.to_string()))?;
        serde_json::from_value(value).map_err(|error| {
            UserSpecError::Model(format!("invalid {USER_SPEC_TOOL} output: {error}"))
        })
    }
}

fn parse_plan_or_terminal(value: &Value) -> Result<Option<EditPlan>, UserSpecError> {
    if value.get("outcome").and_then(Value::as_str) != Some("plan") {
        return Ok(None);
    }
    serde_json::from_value(value.clone())
        .map(Some)
        .map_err(|error| UserSpecError::Edit(format!("invalid PDF edit plan: {error}")))
}

fn draft_response(metadata: UserSpecMetadata, steps: Vec<AgentSpecStep>) -> Value {
    json!({
        "outcome": "draft",
        "draft": AgentDraft {
            name: metadata.name,
            description: metadata.description,
            objective: metadata.objective,
            steps,
        }
    })
}

fn draft_prompt(
    request: &AgentDraftRequest,
    edit_plan: &EditPlan,
) -> Result<String, UserSpecError> {
    Ok(format!(
        "User request:\n{}\n\nConversation history:\n{}\n\nEdit plan summary:\n{}\n\nEdit plan rationale:\n{}\n\nEdit plan steps:\n{}",
        request.user_message,
        format_history(&request.conversation_history),
        edit_plan.summary,
        edit_plan.rationale.as_deref().unwrap_or("None"),
        plan_json(edit_plan)?
    ))
}

fn revision_prompt(
    request: &AgentRevisionRequest,
    edit_plan: &EditPlan,
) -> Result<String, UserSpecError> {
    let current_draft = serde_json::to_string_pretty(&request.current_draft)
        .map_err(|error| UserSpecError::Edit(error.to_string()))?;
    Ok(format!(
        "Revision request:\n{}\n\nConversation history:\n{}\n\nCurrent draft:\n{}\n\nEdit plan summary:\n{}\n\nEdit plan rationale:\n{}\n\nEdit plan steps:\n{}",
        request.user_message,
        format_history(&request.conversation_history),
        current_draft,
        edit_plan.summary,
        edit_plan.rationale.as_deref().unwrap_or("None"),
        plan_json(edit_plan)?
    ))
}

fn plan_json(edit_plan: &EditPlan) -> Result<String, UserSpecError> {
    serde_json::to_string_pretty(edit_plan).map_err(|error| UserSpecError::Edit(error.to_string()))
}

fn format_history(history: &[ConversationMessage]) -> String {
    if history.is_empty() {
        return "None".to_owned();
    }
    history
        .iter()
        .map(|message| format!("- {}: {}", message.role, message.content))
        .collect::<Vec<_>>()
        .join("\n")
}

fn metadata_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "objective": {"type": "string"}
        },
        "required": ["name", "description", "objective"]
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{AgentDraft, AgentSpecStep, UserSpecError, parse_plan_or_terminal};

    #[test]
    fn agent_step_union_round_trips_ai_tools() -> Result<(), Box<dyn std::error::Error>> {
        let draft: AgentDraft = serde_json::from_value(serde_json::json!({
            "name": "Review",
            "description": "Review documents",
            "objective": "Find errors",
            "steps": [{
                "kind": "ai_tool",
                "title": "Audit",
                "description": "Audit figures",
                "tool": "/api/v1/general/rotate-pdf",
                "instruction": "Check all totals"
            }]
        }))?;
        assert!(matches!(draft.steps[0], AgentSpecStep::AiTool { .. }));
        Ok(())
    }

    #[test]
    fn agent_tool_steps_use_catalogued_endpoints_and_exact_parameter_schemas()
    -> Result<(), Box<dyn std::error::Error>> {
        let draft: AgentDraft = serde_json::from_value(json!({
            "name": "Flatten",
            "description": "Flatten documents",
            "objective": "Normalise PDFs",
            "steps": [{
                "kind": "tool",
                "tool": "/api/v1/misc/flatten",
                "parameters": {"flatten_only_forms": true, "render_dpi": 144}
            }]
        }))?;
        assert_eq!(
            serde_json::to_value(&draft)?["steps"][0]["parameters"],
            json!({"flattenOnlyForms": true, "renderDpi": 144})
        );
        let agent_step: AgentDraft = serde_json::from_value(json!({
            "name": "Audit",
            "description": "Audit documents",
            "objective": "Check totals",
            "steps": [{
                "kind": "tool",
                "tool": "/api/v1/ai/tools/math-auditor-agent",
                "parameters": {}
            }]
        }))?;
        assert_eq!(
            serde_json::to_value(agent_step)?["steps"][0]["parameters"],
            json!({"tolerance": "0.01"})
        );

        for invalid_step in [
            json!({
                "kind": "tool",
                "tool": "/api/v1/not-real",
                "parameters": {}
            }),
            json!({
                "kind": "tool",
                "tool": "/api/v1/general/rotate-pdf",
                "parameters": {"flattenOnlyForms": false}
            }),
            json!({
                "kind": "ai_tool",
                "title": "Unknown",
                "description": "Unknown",
                "tool": "/api/v1/not-real",
                "instruction": "Try an unknown endpoint"
            }),
            json!({
                "kind": "ai_tool",
                "title": "Wrong endpoint class",
                "description": "Agent operations are deterministic tool steps",
                "tool": "/api/v1/ai/tools/math-auditor-agent",
                "instruction": "This endpoint is not a generated processing tool"
            }),
        ] {
            let result = serde_json::from_value::<AgentDraft>(json!({
                "name": "Invalid",
                "description": "Invalid",
                "objective": "Invalid",
                "steps": [invalid_step]
            }));
            assert!(result.is_err());
        }
        Ok(())
    }

    #[test]
    fn edit_plan_model_output_rejects_invalid_saved_agent_steps() {
        for (tool, parameters) in [
            ("/api/v1/not-real", json!({})),
            (
                "/api/v1/general/rotate-pdf",
                json!({"flattenOnlyForms": false}),
            ),
        ] {
            let result = parse_plan_or_terminal(&json!({
                "outcome": "plan",
                "summary": "Invalid model output",
                "rationale": "Test",
                "steps": [{"kind": "tool", "tool": tool, "parameters": parameters}],
                "resumeWith": null
            }));
            assert!(matches!(result, Err(UserSpecError::Edit(_))));
        }
    }
}
