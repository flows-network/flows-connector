use axum::{response::IntoResponse, Json};
use serde_json::json;

pub async fn actions() -> impl IntoResponse {
    let events = json!({
        "list": [
            {
                "field": "To request a Pull Request review",
                "value": "request-review",
                "desc": "This connector takes the return value of the flow function to request a GitHub pull request review. It corresponds to the request-review call in the GitHub API."
            },
            {
                "field": "To merge a Pull Request",
                "value": "merge-pull",
                "desc": "This connector takes the return value of the flow function to merge a GitHub pull request. It corresponds to the merge-pull call in the GitHub API."
            },
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
