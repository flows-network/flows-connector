use axum::{Json, response::IntoResponse};
use serde_json::json;

pub async fn actions() -> impl IntoResponse {
    let events = json!({
        "list": [
            {
                "field": "To create an Issue",
                "value": "create-issue",
                "desc": "This connector takes the return value of the flow function to create a new GitHub issue. It corresponds to the create-issue call in the GitHub API."
            },
            {
                "field": "To create a comment",
                "value": "create-comment",
                "desc": "This connector takes the return value of the flow function to create a new GitHub comment for a GitHub issue or Pull Request. It corresponds to the create-comment call in the GitHub API."
            },
            {
                "field": "To add labels",
                "value": "add-labels",
                "desc": "This connector takes the return value of the flow function to add any number of existing label to a GitHub issue or Pull Request. It corresponds to the add-labels call in the GitHub API."
            },
            {
                "field": "To add assignees",
                "value": "add-assignees",
                "desc": "This connector takes the return value of the flow function to add any number of assignees for a GitHub issue or Pull Request. It corresponds to the add-assignees call in the GitHub API."
            },
        ],
    });
    Json(events)
}
