#!/usr/bin/env python3
\"\"\"aws_burp_tunnel_manager.py

Interactive CLI to provision an EC2 instance, allocate an Elastic IP,
and create a reverse SSH tunnel (ELASTIC_IP:REMOTE_PORT -> localhost:LOCAL_BURP_PORT).
Designed for macOS. Uses boto3, paramiko and rich.

REQUIREMENTS:
  - Python 3.8+
  - pip install boto3 botocore paramiko rich
  - AWS CLI profiles or environment credentials available, or supply new keys
  - SSH client available on macOS
USAGE:
  python3 aws_burp_tunnel_manager.py [--dry-run] [--no-cleanup]

WARNING: This script will create real AWS resources (EC2 instance, security group, keypair, Elastic IP)
and will terminate/release them on cleanup. Use with caution and ensure you understand billing implications.
\"\"\"

from __future__ import annotations
import os
import sys
import time
import subprocess
import uuid
import socket
import argparse
import configparser
from pathlib import Path
from typing import Optional, List, Tuple

import boto3
import botocore
import paramiko
from rich.console import Console
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, TimeRemainingColumn

console = Console()
HOME = Path.home()
KEY_DIR = HOME / ".ssh"
KEY_DIR.mkdir(parents=True, exist_ok=True)

# Defaults - change if you prefer
INSTANCE_TYPE = "t3.micro"
LOCAL_BURP_PORT = 8080
REMOTE_PORT_DEFAULT = 9000

# State holder
class State:
    session: Optional[boto3.Session] = None
    ec2_client = None
    ec2_resource = None
    profile_name: Optional[str] = None
    region: Optional[str] = None
    key_name: Optional[str] = None
    key_path: Optional[Path] = None
    security_group_id: Optional[str] = None
    instance_id: Optional[str] = None
    allocation_id: Optional[str] = None
    elastic_ip: Optional[str] = None

state = State()

# ---------------- Utilities ----------------
def list_profiles() -> List[str]:
    sess = boto3.Session()
    return sess.available_profiles or []

def list_regions(session: boto3.Session) -> List[str]:
    ec2 = session.client("ec2")
    resp = ec2.describe_regions(AllRegions=False)
    return [r["RegionName"] for r in resp["Regions"]]

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
    conf[prof_key]["region"] = region
    with open(conf_path, "w") as fh:
        conf.write(fh)

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
            raise RuntimeError(f"Command failed: {cmd}\\nstdout:{res.stdout}\\nstderr:{res.stderr}")
        return res.stdout.strip()
    else:
        res = subprocess.run(cmd, shell=True)
        if check and res.returncode != 0:
            raise RuntimeError(f"Command failed: {cmd}")
        return ""

# ---------------- AWS actions ----------------
def create_keypair_local_and_import(ec2_client, key_basename: str) -> Tuple[str, Path]:
    priv = KEY_DIR / f"{key_basename}"
    pub = priv.with_suffix(".pub")
    if priv.exists() or pub.exists():
        raise FileExistsError(f"Key files {priv} or {pub} already exist")
    run_local(f'ssh-keygen -t ed25519 -N "" -f "{priv}" -C "{key_basename}"')
    if not pub.exists():
        raise RuntimeError("ssh-keygen failed to create public key")
    pub_text = pub.read_text()
    # Import to EC2
    ec2_client.import_key_pair(KeyName=key_basename, PublicKeyMaterial=pub_text)
    state.key_name = key_basename
    state.key_path = priv
    return key_basename, priv

def create_security_group(ec2_client, name: str, my_ssh_cidr: str, remote_port_cidr: str, remote_port: int) -> str:
    vpcs = ec2_client.describe_vpcs()
    vpc_id = vpcs["Vpcs"][0]["VpcId"]
    resp = ec2_client.create_security_group(GroupName=name, Description="burp-tunnel-sg", VpcId=vpc_id)
    sg_id = resp["GroupId"]
    state.security_group_id = sg_id
    # SSH rule
    ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
        'IpProtocol': 'tcp', 'FromPort': 22, 'ToPort': 22,
        'IpRanges': [{'CidrIp': my_ssh_cidr, 'Description': 'SSH from local admin'}]
    }])
    # remote port rule
    ec2_client.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
        'IpProtocol': 'tcp', 'FromPort': int(remote_port), 'ToPort': int(remote_port),
        'IpRanges': [{'CidrIp': remote_port_cidr, 'Description': 'remote port access'}]
    }])
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
        # fallback: describe_images without owner filter and take recent ubuntu pattern
        resp = ec2_client.describe_images(Filters=[{"Name":"name","Values":["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]}])
        images = resp.get("Images", [])
    if not images:
        raise RuntimeError("No Ubuntu AMI found in region")
    images_sorted = sorted(images, key=lambda x: x["CreationDate"], reverse=True)
    return images_sorted[0]["ImageId"]

def launch_instance(ec2_resource, key_name: str, sg_id: str, ami: str, instance_type: str) -> str:
    inst = ec2_resource.create_instances(ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, KeyName=key_name, SecurityGroupIds=[sg_id])[0]
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

def enable_gateway_ports_via_ssh(host_ip: str, username: str, private_key_path: Path):
    key = paramiko.Ed25519Key.from_private_key_file(str(private_key_path))
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(hostname=host_ip, username=username, pkey=key, timeout=30)
    cmd = "sudo sed -i 's/^#\\?GatewayPorts.*/GatewayPorts yes/' /etc/ssh/sshd_config && sudo systemctl restart sshd || sudo service ssh restart"
    stdin, stdout, stderr = c.exec_command(cmd)
    out = stdout.read().decode()
    err = stderr.read().decode()
    c.close()
    return out, err

# ---------------- Cleanup ----------------
def cleanup(show_progress: bool=True):
    console.print(Panel("[red]Cleanup: terminating resources[/red]"))
    steps = ["terminate_instance", "release_eip", "delete_keypair", "delete_sg", "remove_local_keys"]
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), BarColumn(), TimeElapsedColumn()) as prog:
        task = prog.add_task("cleanup", total=len(steps))
        # terminate instance
        if state.instance_id:
            try:
                prog.update(task, description="Terminating EC2 instance...")
                state.ec2_client.terminate_instances(InstanceIds=[state.instance_id])
                waiter = state.ec2_client.get_waiter('instance_terminated')
                waiter.wait(InstanceIds=[state.instance_id])
            except Exception as e:
                console.print(f"[yellow]Warning terminating instance: {e}[/yellow]")
        prog.advance(task)
        # release eip
        if state.allocation_id:
            try:
                prog.update(task, description="Releasing Elastic IP...")
                state.ec2_client.release_address(AllocationId=state.allocation_id)
            except Exception as e:
                console.print(f"[yellow]Warning releasing EIP: {e}[/yellow]")
        prog.advance(task)
        # delete keypair
        if state.key_name:
            try:
                prog.update(task, description="Deleting EC2 keypair...")
                state.ec2_client.delete_key_pair(KeyName=state.key_name)
            except Exception as e:
                console.print(f"[yellow]Warning deleting keypair: {e}[/yellow]")
        prog.advance(task)
        # delete security group
        if state.security_group_id:
            try:
                prog.update(task, description="Deleting security group...")
                state.ec2_client.delete_security_group(GroupId=state.security_group_id)
            except Exception as e:
                console.print(f"[yellow]Warning deleting security group: {e}[/yellow]")
        prog.advance(task)
        # remove local key files
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

# ---------------- Tunnel supervise ----------------
def start_ssh_tunnel(private_key: Path, remote_port: int, local_port: int, elastic_ip: str, max_attempts:int=3):
    ssh_cmd_template = 'ssh -i \"{key}\" -o \"ServerAliveInterval=60\" -o \"ServerAliveCountMax=3\" -o \"ExitOnForwardFailure=yes\" -R 0.0.0.0:{remote}:{local} ubuntu@{eip} -N'
    ssh_cmd = ssh_cmd_template.format(key=private_key, remote=remote_port, local=local_port, eip=elastic_ip)
    attempts = 0
    proc = None

    while attempts < max_attempts:
        attempts += 1
        console.print(f\"[cyan]Starting SSH tunnel (attempt {attempts}/{max_attempts})...[/cyan]\")\n        proc = subprocess.Popen(ssh_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)\n        # give it a brief warmup period\n        time.sleep(2)\n        if proc.poll() is None:\n            console.print(\"[green]SSH tunnel established.[/green]\")\n            return proc\n        else:\n            stderr = proc.stderr.read() if proc.stderr else \"\"\n            console.print(f\"[yellow]Tunnel process exited quickly; stderr:\\n{stderr}[/yellow]\")\n            time.sleep(1)\n    raise RuntimeError(\"Could not establish SSH tunnel after multiple attempts\")\n\n# ---------------- Main flow ----------------\n\ndef main():
    parser = argparse.ArgumentParser(description=\"AWS Burp Tunnel Manager: create EC2+EIP and reverse SSH tunnel\")
    parser.add_argument(\"--dry-run\", action=\"store_true\", help=\"Show actions without making AWS changes\")
    parser.add_argument(\"--no-cleanup\", action=\"store_true\", help=\"Don't automatically cleanup resources on exit (extra confirmation)\")\n    args = parser.parse_args()\n\n    console.clear()\n    console.rule(\"AWS Burp Tunnel Manager — macOS\")\n\n    # Profile selection\n    profiles = list_profiles()\n    console.print(\"Detected AWS CLI profiles:\")\n    tbl = Table()\n    tbl.add_column(\"#\"); tbl.add_column(\"Profile\")\n    for i,p in enumerate(profiles, start=1):\n        tbl.add_row(str(i), p)\n    tbl.add_row(str(len(profiles)+1), \"[bold]Create new profile[/bold]\")\n    console.print(tbl)\n    choice = IntPrompt.ask(f\"Select profile (1-{len(profiles)+1})\", default=1)\n    if choice == len(profiles)+1:\n        prof = Prompt.ask(\"Enter new profile name\", default=f\"burp-tunnel-{int(time.time())}\")\n        access = Prompt.ask(\"AWS Access Key ID\")\n        secret = Prompt.ask(\"AWS Secret Access Key\")\n        # regions list using default session\n        tmp = boto3.Session()\n        regs = list_regions(tmp)\n        console.print(\"Available regions (first 10):\")\n        for i,r in enumerate(regs[:10], start=1):\n            console.print(f\"  {i}) {r}\")\n        r_choice = IntPrompt.ask(f\"Select region (1-{min(10,len(regs))})\", default=1)\n        chosen_region = regs[r_choice-1]\n        save_aws_profile(profile=prof, access_key=access, secret_key=secret, region=chosen_region)\n        state.profile_name = prof\n        state.region = chosen_region\n    else:\n        state.profile_name = profiles[choice-1]\n        # region choice for selected profile\n        sess_temp = boto3.Session(profile_name=state.profile_name)\n        regs = list_regions(sess_temp)\n        console.print(\"Available regions:\")\n        for i,r in enumerate(regs, start=1):\n            console.print(f\"  {i}) {r}\")\n        r_choice = IntPrompt.ask(f\"Select region (1-{len(regs)})\", default=1)\n        state.region = regs[r_choice-1]\n\n    console.print(f\"Using profile: [green]{state.profile_name}[/green], region: [green]{state.region}[/green]\")\n\n    # Init session\n    session = boto3.Session(profile_name=state.profile_name, region_name=state.region)\n    state.session = session\n    state.ec2_client = session.client('ec2')\n    state.ec2_resource = session.resource('ec2')\n\n    # Ports and CIDR\n    local_burp_port = IntPrompt.ask(f\"Local Burp port (default {LOCAL_BURP_PORT})\", default=LOCAL_BURP_PORT)\n    remote_port = IntPrompt.ask(f\"Remote public port (default {REMOTE_PORT_DEFAULT})\", default=REMOTE_PORT_DEFAULT)\n\n    my_ip = detect_public_ip()\n    if my_ip:\n        console.print(f\"Detected your public IP: [green]{my_ip}[/green]\")\n        my_ssh_cidr = f\"{my_ip}/32\"\n    else:\n        ip_in = Prompt.ask(\"Could not auto-detect your public IP. Enter your public IP (x.y.z.w)\")\n        my_ssh_cidr = f\"{ip_in}/32\"\n\n    console.print(\"Choose access for the remote exposed port on EC2:\")\n    console.print(\"  1) Restrict to a CIDR (recommended)\")\n    console.print(\"  2) Allow anywhere (0.0.0.0/0) — not recommended\")\n    ch = IntPrompt.ask(\"Select (1 or 2)\", choices=[\"1\",\"2\"], default=1)\n    if ch == 1:\n        remote_cidr = Prompt.ask(\"Enter CIDR to allow (e.g., 203.0.113.5/32)\")\n    else:\n        remote_cidr = \"0.0.0.0/0\"\n        console.print(\"[yellow]Warning: exposing the remote port to the whole internet.[/yellow]\")\n\n    # Show summary and confirm\n    summary = Table()\n    summary.add_column(\"Action\"); summary.add_column(\"Value\")\n    summary.add_row(\"Profile\", state.profile_name)\n    summary.add_row(\"Region\", state.region)\n    summary.add_row(\"Local Burp port\", str(local_burp_port))\n    summary.add_row(\"Remote public port\", str(remote_port))\n    summary.add_row(\"SSH allowed from\", my_ssh_cidr)\n    summary.add_row(\"Remote port allowed from\", remote_cidr)\n    console.print(Panel(summary, title=\"Planned actions\"))\n    if not Confirm.ask(\"Proceed with the above actions? (type yes to continue)\"):\n        console.print(\"Aborted by user\")\n        sys.exit(0)\n\n    if args.dry_run:\n        console.print(\"[yellow]Dry-run mode: no AWS changes will be made. Exiting.[/yellow]\")\n        sys.exit(0)\n\n    # Deployment steps with progress\n    steps_total = 5\n    with Progress(SpinnerColumn(), TextColumn(\"{task.description}\"), BarColumn(), TimeRemainingColumn()) as progress:\n        task = progress.add_task(\"deploy\", total=steps_total)\n        # step1: key\n        progress.update(task, description=\"[1/5] Creating SSH keypair and importing to EC2\")\n        key_basename = f\"burp_tunnel_{int(time.time())}\"\n        try:\n            create_keypair_local_and_import(state.ec2_client, key_basename)\n        except Exception as e:\n            console.print(f\"[red]Failed to create/import keypair: {e}[/red]\")\n            cleanup()\n            sys.exit(1)\n        progress.advance(task)\n        time.sleep(0.4)\n\n        # step2: security group\n        progress.update(task, description=\"[2/5] Creating security group and ingress rules\")\n        sg_name = f\"sg-burp-tunnel-{int(time.time())}\"\n        try:\n            create_security_group(state.ec2_client, sg_name, my_ssh_cidr, remote_cidr, remote_port)\n        except Exception as e:\n            console.print(f\"[red]Failed to create security group: {e}[/red]\")\n            cleanup()\n            sys.exit(1)\n        progress.advance(task)\n        time.sleep(0.4)\n\n        # step3: launch instance\n        progress.update(task, description=\"[3/5] Finding AMI and launching EC2 instance\")\n        try:\n            ami = find_ubuntu_ami(state.ec2_client)\n            inst_id = launch_instance(state.ec2_resource, state.key_name, state.security_group_id, ami, INSTANCE_TYPE)\n            console.print(f\"Launched instance: [green]{inst_id}[/green]\")\n        except Exception as e:\n            console.print(f\"[red]Failed to launch instance: {e}[/red]\")\n            cleanup()\n            sys.exit(1)\n        progress.advance(task)\n        time.sleep(0.4)\n\n        # step4: allocate EIP\n        progress.update(task, description=\"[4/5] Allocating and associating Elastic IP\")\n        try:\n            alloc, eip = allocate_and_associate_eip(state.ec2_client, state.instance_id)\n            console.print(f\"Elastic IP: [bold]{eip}[/bold]\")\n        except Exception as e:\n            console.print(f\"[red]Failed to allocate/associate EIP: {e}[/red]\")\n            cleanup()\n            sys.exit(1)\n        progress.advance(task)\n        time.sleep(0.4)\n\n        # step5: enable gateway ports\n        progress.update(task, description=\"[5/5] Enabling GatewayPorts on EC2 and finalizing\")\n        console.print(\"Waiting for SSH (port 22) on instance to be reachable...\")\n        start = time.time()\n        while True:\n            try:\n                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n                sock.settimeout(3)\n                sock.connect((state.elastic_ip, 22))\n                sock.close()\n                break\n            except Exception:\n                if time.time() - start > 180:\n                    console.print(\"[red]Timeout waiting for SSH on instance[/red]\")\n                    cleanup()\n                    sys.exit(1)\n                time.sleep(3)\n        try:\n            out, err = enable_gateway_ports_via_ssh(state.elastic_ip, \"ubuntu\", state.key_path)\n            console.print(\"GatewayPorts enabled on remote host\")\n        except Exception as e:\n            console.print(f\"[red]Failed to enable GatewayPorts via SSH: {e}[/red]\")\n            cleanup()\n            sys.exit(1)\n        progress.advance(task)\n        time.sleep(0.4)\n\n    console.print(Panel(f\"[green]Deployment complete[/green]\\nElastic IP: [bold]{state.elastic_ip}[/bold]\\nExpose to company as: {state.elastic_ip}:{remote_port}\", title=\"Success\"))\n\n    # Show verification commands\n    console.rule(\"Verification\")\n    console.print(\"From the EC2 instance run:\\n  curl -v http://127.0.0.1:%d/\\n\" % (remote_port))\n    console.print(\"From any machine run:\\n  curl -v http://%s:%d/\\n\" % (state.elastic_ip, remote_port))\n\n    # Start tunnel\n    console.rule(\"Starting reverse tunnel\")\n    try:\n        proc = start_ssh_tunnel(state.key_path, remote_port, local_burp_port, state.elastic_ip, max_attempts=3)\n    except Exception as e:\n        console.print(f\"[red]Tunnel failed to start: {e}[/red]\")\n        cleanup()\n        sys.exit(1)\n\n    console.print(Panel(\"[green]Tunnel connected ✅\\nType 'exit' to teardown and cleanup.[/green]\", title=\"Status\"))\n\n    # Interactive loop while supervising\n    try:\n        while True:\n            # Check process\n            if proc.poll() is not None:\n                console.print(\"[red]SSH tunnel terminated unexpectedly.[/red]\")\n                # try automatic reconnects\n                reconnected = False\n                for i in range(3):\n                    console.print(f\"Attempting reconnect ({i+1}/3)\")\n                    try:\n                        proc = start_ssh_tunnel(state.key_path, remote_port, local_burp_port, state.elastic_ip, max_attempts=1)\n                        reconnected = True\n                        console.print(\"[green]Reconnected.[/green]\")\n                        break\n                    except Exception as e:\n                        console.print(f\"Reconnect attempt failed: {e}\")\n                        time.sleep(2 ** i)\n                if not reconnected:\n                    console.print(\"[red]Failed to reconnect after 3 attempts.[/red]\")\n                    break\n            # prompt user\n            cmd = Prompt.ask(\"Command (type 'exit' to cleanup)\", default=\"\")\n            if cmd.strip().lower() == \"exit\":\n                console.print(\"Exit requested — cleaning up\")\n                break\n            elif cmd.strip() == \"\":\n                continue\n            else:\n                console.print(\"Unknown command. Type 'exit' to stop and cleanup.\")\n    except KeyboardInterrupt:\n        console.print(\"KeyboardInterrupt — cleaning up\")\n\n    # Teardown\n    if args.no_cleanup:\n        console.print(\"--no-cleanup specified: leaving resources running. You must clean them manually later.\")\n        console.print(f\"Instance: {state.instance_id}, Elastic IP: {state.elastic_ip}\")\n        sys.exit(0)\n\n    console.print(\"Starting cleanup...\")\n    try:\n        if proc and proc.poll() is None:\n            proc.terminate()\n            try:\n                proc.wait(timeout=5)\n            except Exception:\n                proc.kill()\n    except Exception:\n        pass\n\n    cleanup()\n    console.print(\"Done. Exiting.\")\n\nif __name__ == '__main__':\n    main()\n