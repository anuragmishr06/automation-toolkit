from urllib.parse import urlparse

def extract_bucket_name(url):
    try:
        parsed = urlparse(url)
        host_parts = parsed.netloc.split('.')
        if 's3' in host_parts:
            return host_parts[0]  # e.g., bucket-name from bucket-name.s3.amazonaws.com
    except Exception:
        pass
    return None

input_file = 'bucket-url-list.txt'
output_file = 'bucket-name-list.txt'

bucket_names = []

with open(input_file, 'r') as f:
    for line in f:
        url = line.strip()
        if not url:
            continue
        name = extract_bucket_name(url)
        if name:
            bucket_names.append(name)

# Remove duplicates and save
bucket_names = sorted(set(bucket_names))

with open(output_file, 'w') as f:
    for name in bucket_names:
        f.write(name + '\n')

print(f"✅ Extracted {len(bucket_names)} bucket names to {output_file}")

