from jira import JIRA

# --- Configuration ---
JIRA_URL = 'https://xyZ.atlassian.net'
EMAIL = 'your-email@example.com'         # Your Atlassian email
API_TOKEN = 'your-api-token'             # Your Atlassian API token

JQL_QUERY = '''
reporter = REPORTER_NAME AND project = SV AND status = Open AND assignee = EMPTY
'''

COMMENT = ("COMMENT")

TRANSITION_IDS = {
    'Resolved': '121', //FROM-JIRA-STATES.PY
    'Remediated': '71'
}

# --- Connect to JIRA ---
jira = JIRA(server=JIRA_URL, basic_auth=(EMAIL, API_TOKEN))

# --- Fetch issues ---
issues = jira.search_issues(JQL_QUERY, maxResults=1000)

for issue in issues:
    print(f"\nProcessing {issue.key} - Status: {issue.fields.status.name}")

    # Add comment
    jira.add_comment(issue, COMMENT)
    print(f"Added comment to {issue.key}")

    current_status = issue.fields.status.name

    # Transition to Resolved if in Open
    if current_status == 'Open':
        jira.transition_issue(issue, TRANSITION_IDS['Resolved'])
        print(f"Transitioned {issue.key} to Resolved")

        # Refresh issue after transition
        issue = jira.issue(issue.key)

    # Transition to Remediated if in Resolved
    if issue.fields.status.name == 'Resolved':
        jira.transition_issue(issue, TRANSITION_IDS['Remediated'])
        print(f"Transitioned {issue.key} to Remediated")
