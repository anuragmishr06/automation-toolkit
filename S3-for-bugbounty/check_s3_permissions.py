import subprocess
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from time import sleep

# Create rich console
console = Console()

# Load bucket names
with open("bucket-name-list.txt", "r") as f:
    bucket_names = [line.strip() for line in f if line.strip()]

# Define permission checks
PERMISSIONS = {
    "ListBucket": [
        ["aws", "s3", "ls", "s3://{bucket}/", "--no-sign-request"]
    ],
    "GetObject": [
        ["aws", "s3api", "list-objects", "--bucket", "{bucket}", "--max-items", "1", "--no-sign-request"]
    ],
    "PutObject": [
        ["aws", "s3", "cp", "dummy.txt", "s3://{bucket}/", "--no-sign-request"]
    ],
    "DeleteObject": [
        ["aws", "s3api", "delete-object", "--bucket", "{bucket}", "--key", "nonexistent.txt", "--no-sign-request"]
    ],
    "ListBucketVersions": [
        ["aws", "s3api", "list-object-versions", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "ListMultipartUploads": [
        ["aws", "s3api", "list-multipart-uploads", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "GetBucketLocation": [
        ["aws", "s3api", "get-bucket-location", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "GetBucketAcl": [
        ["aws", "s3api", "get-bucket-acl", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "GetBucketPolicy": [
        ["aws", "s3api", "get-bucket-policy", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "GetBucketCors": [
        ["aws", "s3api", "get-bucket-cors", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "GetBucketWebsite": [
        ["aws", "s3api", "get-bucket-website", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "GetBucketLifecycle": [
        ["aws", "s3api", "get-bucket-lifecycle-configuration", "--bucket", "{bucket}", "--no-sign-request"]
    ],
    "GetObjectAcl": [
        ["aws", "s3api", "get-object-acl", "--bucket", "{bucket}", "--key", "nonexistent.txt", "--no-sign-request"]
    ],
    "HeadBucket": [
        ["aws", "s3api", "head-bucket", "--bucket", "{bucket}", "--no-sign-request"]
    ],
}

# Create dummy file for put-object test
with open("dummy.txt", "w") as f:
    f.write("test")

# Loop through each bucket
for bucket in bucket_names:
    table = Table(title=f"🧪 Checking Bucket: [bold cyan]{bucket}[/bold cyan]", show_lines=True)
    table.add_column("Permission", style="bold")
    table.add_column("Status")

    for permission, commands in PERMISSIONS.items():
        allowed = False
        for cmd_template in commands:
            cmd = [arg.replace("{bucket}", bucket) for arg in cmd_template]
            try:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                allowed = True
                break
            except subprocess.CalledProcessError:
                continue

        status = "[green]allowed[/green]" if allowed else "[red]not allowed[/red]"
        table.add_row(permission, status)

    console.print(table)
    sleep(0.5)

# Cleanup
subprocess.run(["rm", "-f", "dummy.txt"])

