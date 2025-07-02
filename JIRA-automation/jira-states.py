from jira import JIRA

# --- Configuration ---
JIRA_URL = 'https://xyZ.atlassian.net'
EMAIL = 'anurag@xyz.com'      # Your Atlassian email
API_TOKEN = 'JIRA-TOKEN'
ISSUE_KEY = 'ISSUE_ID'                # Replace with a real issue key from your filter

# --- Connect to JIRA ---
jira = JIRA(server=JIRA_URL, basic_auth=(EMAIL, API_TOKEN))

# --- Get transitions ---
transitions = jira.transitions(ISSUE_KEY)

print(f"Available transitions for {ISSUE_KEY}:\n")
for t in transitions:
    print(f"Name: {t['name']}, ID: {t['id']}")
