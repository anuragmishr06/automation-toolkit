# Scripts for

- extracting bucket names from the S3 URLs -> extract_bucket_names.py
- Scan to check what actions can be done unauthenticated(without access key and secrets) on those buckets -> check_s3_permissions.py
- Script to download sensitive files from S3 bucket to local like - Javascript, ssh key etc. and then run secret scanners(like trufflehog,gitleaks) on it to identify secrets in the bucket -> download_sensitive_s3_files.py
