#!/usr/bin/env python3
"""aws_burp_tunnel_manager_v3.py

AWS Burp Tunnel Manager v3 (macOS)
- Fully automatic: EC2 + Elastic IP + IAM role for SSM + Squid installed via user-data
- Uses SSM Session Manager port forwarding to expose Squid on localhost
  so Burp traffic exits the Elastic IP (no dependency on home IP)
- Interactive terminal UI with rich, progress bars, and automatic cleanup
- --dry-run and --no-cleanup supported

Prereqs on your Mac:
  - Python 3.8+ with boto3, botocore, paramiko, rich
    pip3 install boto3 botocore paramiko rich
  - AWS CLI installed and configured (or provide keys when prompted)
  - session-manager-plugin installed (for aws ssm start-session port forwarding)
    https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html

Security notes:
  - This script will create IAM role and instance profile. Ensure your AWS user has permissions
    to create IAM roles, attach policies, and create EC2 resources. Removed on cleanup.
  - Review user-data and policies before running in production.
"""

from __future__ import annotations
import os, sys, time, subprocess, uuid, socket, json, argparse, configparser
from pathlib import Path
from typing import Optional, List, Tuple

import boto3, botocore
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, TimeElapsedColumn

console = Console()
HOME = Path.home()
KEY_DIR = HOME / ".ssh"
KEY_DIR.mkdir(parents=True, exist_ok=True)

# Defaults
DEFAULT_REGION = "us-east-1"
INSTANCE_TYPE = "t3.micro"
LOCAL_SQUID_PORT = 3128   # local port forwarded to remote squid
REMOTE_SQUID_PORT = 3128  # squid listens on 127.0.0.1:3128 on the instance
LOCAL_BURP_PORT = 8080    # your burp local port (if needed for mapping)
REMOTE_PORT_DEFAULT = 9000

# IAM role/profile defaults (unique names)
ROLE_NAME_PREFIX = "BurpSSMRole"
PROFILE_NAME_PREFIX = "BurpSSMProfile"

# state
class State:
    session: Optional[boto3.Session] = None
    ec2_client = None
    ec2_resource = None
    iam_client = None
    ssm_client = None
    profile_name: Optional[str] = None
    region: Optional[str] = None
    key_name: Optional[str] = None
    key_path: Optional[Path] = None
    security_group_id: Optional[str] = None
    instance_id: Optional[str] = None
    allocation_id: Optional[str] = None
    elastic_ip: Optional[str] = None
    iam_role_name: Optional[str] = None
    iam_instance_profile: Optional[str] = None
    ssm_session_proc: Optional[subprocess.Popen] = None

state = State()

REGION_NAMES = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ca-central-1": "Canada (Central)",
    "eu-central-1": "Europe (Frankfurt)",
    "eu-west-1": "Europe (Ireland)",
    "eu-west-2": "Europe (London)",
    "eu-west-3": "Europe (Paris)",
    "eu-north-1": "Europe (Stockholm)",
    "sa-east-1": "South America (São Paulo)",
}

# ---------------- utilities ----------------
def detect_public_ip() -> Optional[str]:
    try:
        import urllib.request
        with urllib.request.urlopen("https://ifconfig.me/ip", timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        return None

def run_local(cmd: str, capture: bool=False, check: bool=True) -> str:
    console.log(f"[local] {cmd}")
    if capture:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check and res.returncode != 0:
            raise RuntimeError(f"Command failed: {cmd}\nstdout:{res.stdout}\nstderr:{res.stderr}")
        return res.stdout.strip()
    else:
        res = subprocess.run(cmd, shell=True)
        if check and res.returncode != 0:
            raise RuntimeError(f"Command failed: {cmd}")
        return ""

def list_profiles() -> List[str]:
    sess = boto3.Session()
    return sess.available_profiles or []

def list_regions(session: boto3.Session) -> List[Tuple[str, str]]:
    try:
        ec2 = session.client("ec2")
        resp = ec2.describe_regions(AllRegions=False)
        region_codes = [r["RegionName"] for r in resp["Regions"]]
    except (botocore.exceptions.NoRegionError, botocore.exceptions.NoCredentialsError, botocore.exceptions.EndpointConnectionError):
        console.print("[yellow]No AWS config or network — using static region list[/yellow]")
        region_codes = list(REGION_NAMES.keys())
    return [(REGION_NAMES.get(code, code), code) for code in region_codes]

def save_aws_profile(profile: str, access_key: str, secret_key: str, region: str):
    cred_path = HOME / ".aws" / "credentials"
    conf_path = HOME / ".aws" / "config"
    cred_path.parent.mkdir(parents=True, exist_ok=True)
    cfg = configparser.ConfigParser()
    if cred_path.exists():
        cfg.read(cred_path)
    cfg[profile] = {}
    cfg[profile]["aws_access_key_id"] = access_key
    cfg[profile]["aws_secret_access_key"] = secret_key
    with open(cred_path, "w") as fh:
        cfg.write(fh)
    conf = configparser.ConfigParser()
    if conf_path.exists():
        conf.read(conf_path)
    prof_key = f"profile {profile}" if profile != "default" else "default"
    if prof_key not in conf:
        conf[prof_key] = {}
    conf[prof_key]["region"] = str(region)
    with open(conf_path, "w") as fh:
        conf.write(fh)

# ---------------- AWS helper actions ----------------
def create_keypair_local_and_import(ec2_client, key_basename: str):
    priv = KEY_DIR / f"{key_basename}"
    pub = priv.with_suffix(".pub")
    if priv.exists() or pub.exists():
        raise FileExistsError(f"Key files {priv} or {pub} already exist")
    run_local(f'ssh-keygen -t ed25519 -N "" -f "{priv}" -C "{key_basename}"')
    if not pub.exists():
        raise RuntimeError("ssh-keygen failed to create public key")
    pub_text = pub.read_text()
    ec2_client.import_key_pair(KeyName=key_basename, PublicKeyMaterial=pub_text)
    state.key_name = key_basename
    state.key_path = priv
    return key_basename, priv

def create_security_group(ec2_client, name: str, my_ssh_cidr: str, squid_cidr: str, squid_port: int) -> str:
    vpcs = ec2_client.describe_vpcs()
    vpc_id = vpcs["Vpcs"][0]["VpcId"]
    resp = ec2_client.create_security_group(GroupName=name, Description="burp-ssm-squid-sg", VpcId=vpc_id)
    sg_id = resp["GroupId"]
    state.security_group_id = sg_id
    try:
        if my_ssh_cidr:
            ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
                'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
                'IpRanges': [{'CidrIp': my_ssh_cidr, 'Description': 'SSH from local admin'}]
            }])
    except Exception:
        pass
    return sg_id

def find_ubuntu_ami(ec2_client) -> str:
    filters = [
        {"Name":"name", "Values":["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]},
        {"Name":"architecture","Values":["x86_64"]}
    ]
    try:
        resp = ec2_client.describe_images(Owners=["099720109477"], Filters=filters)
        images = resp.get("Images", [])
    except botocore.exceptions.ClientError:
        images = []
    if not images:
        resp = ec2_client.describe_images(Filters=[{"Name":"name","Values":["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]}])
        images = resp.get("Images", [])
    if not images:
        raise RuntimeError("No Ubuntu AMI found in region")
    images_sorted = sorted(images, key=lambda x: x["CreationDate"], reverse=True)
    return images_sorted[0]["ImageId"]

def launch_instance_with_ssm(ec2_resource, key_name: str, sg_id: str, ami: str, instance_type: str, iam_profile_name: str, user_data: str) -> str:
    inst = ec2_resource.create_instances(ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1,
                                         KeyName=key_name, SecurityGroupIds=[sg_id],
                                         IamInstanceProfile={'Name': iam_profile_name},
                                         UserData=user_data)[0]
    state.instance_id = inst.id
    inst.wait_until_running()
    inst.load()
    return inst.id

def allocate_and_associate_eip(ec2_client, instance_id: str) -> Tuple[str,str]:
    a = ec2_client.allocate_address(Domain='vpc')
    alloc_id = a['AllocationId']
    eip = a['PublicIp']
    ec2_client.associate_address(InstanceId=instance_id, AllocationId=alloc_id)
    state.allocation_id = alloc_id
    state.elastic_ip = eip
    return alloc_id, eip

# ---------------- IAM helpers ----------------
def create_iam_role_for_ssm(iam_client, role_name: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ]
    }
    try:
        iam_client.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    except iam_client.exceptions.EntityAlreadyExistsException:
        console.print(f"[yellow]IAM role {role_name} already exists — reusing[/yellow]")
    iam_client.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
    profile_name = f"{role_name}-profile"
    try:
        iam_client.create_instance_profile(InstanceProfileName=profile_name)
    except iam_client.exceptions.EntityAlreadyExistsException:
        pass
    try:
        iam_client.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    except Exception:
        pass
    state.iam_role_name = role_name
    state.iam_instance_profile = profile_name
    return profile_name

# ---------------- user data ----------------
def build_user_data_for_ssm_and_squid(region: str) -> str:
    # Template to install SSM agent and squid and configure squid to listen on 127.0.0.1:3128
    ud = '''#!/bin/bash
set -e
apt-get update -y
apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release unzip
if ! command -v amazon-ssm-agent >/dev/null 2>&1; then
  if command -v snap >/dev/null 2>&1; then
    snap install amazon-ssm-agent --classic || true
    systemctl enable --now snap.amazon-ssm-agent.amazon-ssm-agent.service || true
  fi
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y squid || true
cat > /etc/squid/squid.conf <<'EOF'
http_port 127.0.0.1:3128
acl localnet src 127.0.0.1/32
http_access allow localnet
http_access deny all
cache_dir ufs /var/spool/squid 100 16 256
access_log stdio:/var/log/squid/access.log
EOF
systemctl restart squid || service squid restart || true
'''
    return ud

# ---------------- cleanup ----------------
def cleanup(show_progress: bool=True):
    console.print(Panel("[red]Cleanup: terminating resources[/red]"))
    steps = ["terminate_instance","release_eip","remove_iam_instance_profile","delete_iam_role","delete_keypair","delete_sg","remove_local_keys"]
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeRemainingColumn()) as prog:
        task = prog.add_task("cleanup", total=len(steps))
        if state.instance_id:
            try:
                prog.update(task, description="Terminating EC2 instance...")
                state.ec2_client.terminate_instances(InstanceIds=[state.instance_id])
                waiter = state.ec2_client.get_waiter('instance_terminated')
                waiter.wait(InstanceIds=[state.instance_id])
            except Exception as e:
                console.print(f"[yellow]Warning terminating instance: {e}[/yellow]")
        prog.advance(task)
        if state.allocation_id:
            try:
                prog.update(task, description="Releasing Elastic IP...")
                state.ec2_client.release_address(AllocationId=state.allocation_id)
            except Exception as e:
                console.print(f"[yellow]Warning releasing EIP: {e}[/yellow]")
        prog.advance(task)
        if state.iam_instance_profile and state.iam_role_name:
            try:
                prog.update(task, description="Removing IAM instance profile...")
                state.iam_client.remove_role_from_instance_profile(InstanceProfileName=state.iam_instance_profile, RoleName=state.iam_role_name)
                state.iam_client.delete_instance_profile(InstanceProfileName=state.iam_instance_profile)
            except Exception as e:
                console.print(f"[yellow]Warning removing instance profile: {e}[/yellow]")
        prog.advance(task)
        if state.iam_role_name:
            try:
                prog.update(task, description="Deleting IAM role...")
                state.iam_client.detach_role_policy(RoleName=state.iam_role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore")
                state.iam_client.delete_role(RoleName=state.iam_role_name)
            except Exception as e:
                console.print(f"[yellow]Warning deleting role: {e}[/yellow]")
        prog.advance(task)
        if state.key_name:
            try:
                prog.update(task, description="Deleting EC2 keypair...")
                state.ec2_client.delete_key_pair(KeyName=state.key_name)
            except Exception as e:
                console.print(f"[yellow]Warning deleting keypair: {e}[/yellow]")
        prog.advance(task)
        if state.security_group_id:
            try:
                prog.update(task, description="Deleting security group...")
                state.ec2_client.delete_security_group(GroupId=state.security_group_id)
            except Exception as e:
                console.print(f"[yellow]Warning deleting security group: {e}[/yellow]")
        prog.advance(task)
        if state.key_path and state.key_path.exists():
            try:
                prog.update(task, description="Removing local key files...")
                pub = state.key_path.with_suffix('.pub')
                state.key_path.unlink()
                if pub.exists():
                    pub.unlink()
            except Exception as e:
                console.print(f"[yellow]Warning removing local keys: {e}[/yellow]")
        prog.advance(task)
    console.print("[green]Cleanup finished.[/green]")

# ---------------- SSM port forwarding ----------------
def start_ssm_port_forward(instance_id: str, region: str, local_port: int, remote_host: str, remote_port: int) -> subprocess.Popen:
    cmd = [
        "aws","ssm","start-session",
        "--target", instance_id,
        "--document-name", "AWS-StartPortForwardingSessionToRemoteHost",
        "--parameters", f"host={remote_host},portNumber={remote_port},localPortNumber={local_port}",
        "--region", region
    ]
    console.print(f"[cyan]Starting SSM port-forward (local {local_port} -> {remote_host}:{remote_port}) using aws cli[/cyan]")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2)
    if proc.poll() is not None:
        out, err = proc.communicate(timeout=2)
        raise RuntimeError(f"SSM session failed to start. stdout:\n{out}\nstderr:\n{err}")
    return proc

# ---------------- main flow ----------------
def main():
    parser = argparse.ArgumentParser(description="AWS Burp Tunnel Manager v3: EC2+EIP + SSM+Squid reverse proxy")
    parser.add_argument("--dry-run", action="store_true", help="Show actions without making AWS changes")
    parser.add_argument("--no-cleanup", action="store_true", help="Leave resources running on exit (careful!)")
    args = parser.parse_args()

    console.clear()
    console.rule("[bold cyan]AWS Burp Tunnel Manager v3 — macOS[/bold cyan]")

    console.print(Panel("[bold]AWS Account & Region Setup[/bold]\nChoose an existing profile or create a new one. The chosen region will be used for deployment.", subtitle="Step 1 of 4"))

    profiles = list_profiles()
    tbl = Table(); tbl.add_column("#"); tbl.add_column("Profile")
    for i,p in enumerate(profiles, start=1): tbl.add_row(str(i), p)
    tbl.add_row(str(len(profiles)+1), "[bold]Create new profile[/bold]")
    console.print(tbl)
    choice = IntPrompt.ask(f"Select profile (1-{len(profiles)+1})", default=1)

    if choice == len(profiles)+1:
        prof = Prompt.ask("Enter new profile name", default=f"burp-ssm-{int(time.time())}")
        access = Prompt.ask("AWS Access Key ID"); secret = Prompt.ask("AWS Secret Access Key")
        tmp = boto3.Session(); regions = list_regions(tmp)
        console.print("\nSelect a region for deployment:")
        rtbl = Table(show_header=True, header_style="bold magenta"); rtbl.add_column("#"); rtbl.add_column("Region Name"); rtbl.add_column("Region Code")
        for i,(label,code) in enumerate(regions, start=1): rtbl.add_row(str(i), label, code)
        console.print(rtbl)
        r_choice = IntPrompt.ask(f"Select region (1-{len(regions)})", default=1)
        chosen_region = regions[r_choice-1][1] if isinstance(regions[r_choice-1], (list,tuple)) else regions[r_choice-1]
        save_aws_profile(profile=prof, access_key=access, secret_key=secret, region=chosen_region)
        state.profile_name = prof; state.region = chosen_region
    else:
        state.profile_name = profiles[choice-1]
        sess_temp = boto3.Session(profile_name=state.profile_name); regions = list_regions(sess_temp)
        console.print("\nSelect a region for deployment:")
        rtbl = Table(show_header=True, header_style="bold magenta"); rtbl.add_column("#"); rtbl.add_column("Region Name"); rtbl.add_column("Region Code")
        for i,(label,code) in enumerate(regions, start=1): rtbl.add_row(str(i), label, code)
        console.print(rtbl)
        r_choice = IntPrompt.ask(f"Select region (1-{len(regions)})", default=1)
        state.region = regions[r_choice-1][1] if isinstance(regions[r_choice-1], (list,tuple)) else regions[r_choice-1]

    console.print(f"Using profile: [green]{state.profile_name}[/green], region: [green]{state.region}[/green]\n")

    session = boto3.Session(profile_name=state.profile_name, region_name=state.region)
    state.session = session; state.ec2_client = session.client('ec2'); state.ec2_resource = session.resource('ec2')
    state.iam_client = session.client('iam'); state.ssm_client = session.client('ssm')

    console.print(Panel("[bold]Network & Ports[/bold]\nThis tool will create an EC2 with Squid (proxy) and expose it via SSM port-forwarding so that Burp traffic exits the Elastic IP.", subtitle="Step 2 of 4"))

    local_squid_port = IntPrompt.ask(f"Local Squid port to forward (default {LOCAL_SQUID_PORT})", default=LOCAL_SQUID_PORT)
    remote_squid_port = REMOTE_SQUID_PORT
    local_burp_port = IntPrompt.ask(f"Local Burp port (if you want to map; default {LOCAL_BURP_PORT})", default=LOCAL_BURP_PORT)

    my_ip = detect_public_ip()
    if my_ip:
        my_ssh_cidr = f"{my_ip}/32"
        console.print(f"Detected public IP: [green]{my_ip}[/green] — will restrict SSH to {my_ssh_cidr} if created")
    else:
        my_ssh_cidr = None; console.print("[yellow]Could not auto-detect your public IP. SSH restriction will be skipped.[/yellow]")

    console.print("\n"); console.rule("Summary of planned actions")
    s_tbl = Table(); s_tbl.add_column("Item"); s_tbl.add_column("Value")
    s_tbl.add_row("Profile", state.profile_name); s_tbl.add_row("Region", state.region)
    s_tbl.add_row("Local Squid port", str(local_squid_port)); s_tbl.add_row("Remote Squid port", str(remote_squid_port))
    s_tbl.add_row("Local Burp port", str(local_burp_port)); s_tbl.add_row("SSH allowed from", my_ssh_cidr or "(not detected)")
    console.print(Panel(s_tbl))
    if not Confirm.ask("Proceed with these actions?", default=True): console.print("Aborted by user"); sys.exit(0)
    if args.dry_run: console.print("[yellow]Dry-run: no AWS changes will be made. Exiting.[/yellow]"); sys.exit(0)

    console.print("\n"); console.rule("Deployment — creating resources")
    steps = ["Create keypair", "Create security group", "Create IAM role/profile", "Launch EC2", "Allocate & associate EIP", "Wait for SSM & start port-forward"]
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeRemainingColumn()) as progress:
        task = progress.add_task("deploy", total=len(steps))
        progress.update(task, description="[1/6] Creating SSH keypair and importing to EC2")
        key_basename = f"burp_ssm_{int(time.time())}"
        try: create_keypair_local_and_import(state.ec2_client, key_basename)
        except Exception as e: console.print(f"[red]Failed to create/import keypair: {e}[/red]"); cleanup(); sys.exit(1)
        progress.advance(task); time.sleep(0.2)

        progress.update(task, description="[2/6] Creating security group")
        sg_name = f"burp-ssm-sg-{int(time.time())}"
        try: create_security_group(state.ec2_client, sg_name, my_ssh_cidr, "127.0.0.1/32", remote_squid_port)
        except Exception as e: console.print(f"[red]Failed to create security group: {e}[/red]"); cleanup(); sys.exit(1)
        progress.advance(task); time.sleep(0.2)

        progress.update(task, description="[3/6] Creating IAM role & instance profile for SSM")
        role_name = f"{ROLE_NAME_PREFIX}-{int(time.time())}"
        try: profile_name = create_iam_role_for_ssm(state.iam_client, role_name); console.print(f"IAM instance profile: [green]{profile_name}[/green] (role: {role_name})")
        except Exception as e: console.print(f"[red]Failed to create IAM role/profile: {e}[/red]"); cleanup(); sys.exit(1)
        progress.advance(task); time.sleep(0.2)

        progress.update(task, description="[4/6] Finding AMI and launching EC2 instance (with user-data)")
        try:
            ami = find_ubuntu_ami(state.ec2_client)
            user_data = build_user_data_for_ssm_and_squid(state.region)
            inst_id = launch_instance_with_ssm(state.ec2_resource, state.key_name, state.security_group_id, ami, INSTANCE_TYPE, profile_name, user_data)
            console.print(f"Launched instance: [green]{inst_id}[/green]")
        except Exception as e: console.print(f"[red]Failed to launch instance: {e}[/red]"); cleanup(); sys.exit(1)
        progress.advance(task); time.sleep(0.2)

        progress.update(task, description="[5/6] Allocating and associating Elastic IP")
        try: alloc, eip = allocate_and_associate_eip(state.ec2_client, state.instance_id); console.print(f"Elastic IP: [bold]{eip}[/bold]")
        except Exception as e: console.print(f"[red]Failed to allocate/associate EIP: {e}[/red]"); cleanup(); sys.exit(1)
        progress.advance(task); time.sleep(0.2)

        progress.update(task, description="[6/6] Waiting for SSM agent and starting port-forward")
        try:
            found = False
            for _ in range(60):
                try:
                    resp = state.ssm_client.describe_instance_information(Filters=[{'Key':'InstanceIds','Values':[state.instance_id]}])
                    if resp.get('InstanceInformationList'): found = True; break
                except Exception: pass
                time.sleep(3)
            if not found: raise RuntimeError("Instance never appeared in SSM. Check IAM role and network connectivity.")
            proc = start_ssm_port_forward(state.instance_id, state.region, local_squid_port, "127.0.0.1", remote_squid_port)
            state.ssm_session_proc = proc
            console.print(f"[green]SSM port-forward started (local {local_squid_port} -> remote 127.0.0.1:{remote_squid_port})[/green]")
        except Exception as e: console.print(f"[red]Failed to start SSM port-forward: {e}[/red]"); cleanup(); sys.exit(1)
        progress.advance(task); time.sleep(0.2)

    console.print(Panel(f"[green]Deployment complete[/green]\nElastic IP: [bold]{state.elastic_ip}[/bold]\nConfigure Burp's upstream proxy to http://127.0.0.1:{local_squid_port}", title="Success"))

    console.rule("Verification")
    try:
        out = run_local(f"curl -sS -x http://127.0.0.1:{local_squid_port} https://ifconfig.me", capture=True, check=False)
        console.print("Quick check (curl via forwarded Squid):"); console.print(out.strip()[:200] if out else "[no output]")
    except Exception as e:
        console.print(f"[yellow]Quick verification failed (non-fatal): {e}[/yellow]")

    console.rule("Status — tunnel running")
    console.print(Panel("[green]Tunnel & proxy running locally.[/green]\nType 'exit' to teardown and cleanup.", title="Status"))

    try:
        while True:
            cmd = Prompt.ask("Command (type 'exit' to cleanup)", default="")
            if cmd.strip().lower() == "exit": console.print("Exit requested — cleaning up"); break
            elif cmd.strip() == "": continue
            else: console.print("Unknown command. Type 'exit' to stop and cleanup.")
    except KeyboardInterrupt:
        console.print("KeyboardInterrupt — cleaning up")

    if args.no_cleanup:
        console.print("--no-cleanup specified: leaving resources running. You must clean them manually later.")
        console.print(f"Instance: {state.instance_id}, Elastic IP: {state.elastic_ip}, IAM profile: {state.iam_instance_profile}")
        sys.exit(0)

    console.print("Starting cleanup...")
    try:
        if state.ssm_session_proc and state.ssm_session_proc.poll() is None:
            state.ssm_session_proc.terminate()
            try: state.ssm_session_proc.wait(timeout=3)
            except: state.ssm_session_proc.kill()
    except Exception: pass
    cleanup()
    console.print("Done. Exiting.")

if __name__ == '__main__':
    main()
