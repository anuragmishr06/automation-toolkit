# AWS Burp Tunnel Manager

A macOS-focused Python CLI tool that provisions a temporary AWS EC2 instance, allocates an Elastic (static) IP,
and starts a reverse SSH tunnel so you can expose your local Burp Suite (or any local TCP service)
to the public IP for whitelisting by a third-party application.

> **Warning**: this tool creates AWS resources (EC2 instance, security group, keypair, Elastic IP).
> Ensure you have appropriate AWS permissions and understand possible costs. Clean up resources when finished.

## Files
- `aws_burp_tunnel_manager.py` — main executable script.
- `README.md` — this file.

## Features
- Select AWS region from the list of available regions.
- Choose an existing AWS CLI profile or create a new one (saves to `~/.aws/credentials`).
- Create/import an SSH key pair and upload public key to EC2.
- Create a security group (restrict SSH to your IP, open remote port for company whitelisting).
- Launch Ubuntu EC2 instance (`t3.micro` by default), allocate & associate Elastic IP.
- Enable `GatewayPorts` on EC2 so `ssh -R` can bind to external interfaces.
- Start and supervise a reverse SSH tunnel: `ELASTIC_IP:REMOTE_PORT -> localhost:LOCAL_BURP_PORT`.
- Automatic reconnect attempts (3 retries). Interactive prompt; type `exit` to cleanup.
- Cleanup routine to terminate instance, release Elastic IP, delete keypair & security group and local key files.
- `--dry-run` and `--no-cleanup` options.

## Prerequisites
- macOS
- Python 3.8+
- AWS account and an IAM user with EC2 permissions:
  - ec2:DescribeRegions, RunInstances, AllocateAddress, AssociateAddress, ReleaseAddress,
  - TerminateInstances, DescribeInstances, Create/Delete keypairs, Create/Delete security groups, etc.
- Install dependencies:
```bash
pip3 install boto3 botocore paramiko rich
```

- Ensure `ssh` is installed (standard on macOS). Optionally `autossh` for more robust tunnels.

## Setup AWS Credentials
You can use an existing AWS CLI profile or create a new one when prompted by the script.

To configure an AWS profile manually:
```bash
aws configure --profile myprofile
```

## Usage
Run the script in Terminal:
```bash
python3 aws_burp_tunnel_manager.py
```

Options:
- `--dry-run` — print planned actions and exit without making AWS changes.
- `--no-cleanup` — do not cleanup on exit (useful for debugging). NOTE: resources will remain and may incur cost.

Follow prompts to:
1. Choose or create an AWS profile.
2. Select a region.
3. Provide local Burp port (default 8080) and remote public port to expose on the Elastic IP (default 9000).
4. Confirm planned actions.

After deployment, the script prints the Elastic IP. Provide this IP (and the remote port) to the company for whitelisting (e.g., `3.120.45.10:9000`).

## Verify the tunnel
Once the tunnel is up, run these checks:

From the terminal:
```bash
aws ssm start-session   --target <PASTE-INSTANCE-ID>  --document-name AWS-StartPortForwardingSessionToRemoteHost   --parameters '{"host":["127.0.0.1"],"portNumber":["3128"],"localPortNumber":["3128"]}'   --region ap-south-1   --profile static-ip
```
From another terminal:
```bash
nc -vz 127.0.0.1 3128 || true
```

```bash
curl -sS -x http://127.0.0.1:3128 https://ifconfig.me && echo
```

You will see the Elastic IP value if the static IP is setup properly. 

# Setup Upstream Proxy in burp:
Go to proxy settings -> user -> Network -> Connections -> Upstream Proxy server

Destination host: *
Proxy host: 127.0.0.1
Proxy port: 3128
Authentication type: None


After this You should see the request appear in Burp Suite if the tunnel is working correctly.


## Security notes
- Do **not** expose remote port to `0.0.0.0/0` unless absolutely necessary. Prefer restricting to the company's CIDR.
- The script uploads your generated SSH public key to EC2. The private key remains on your machine (in `~/.ssh/`).
- Cleanup is critical. Use the script's cleanup routine or manually terminate and release resources from the AWS Console.

## Troubleshooting
- If the script fails due to permission issues, ensure the IAM user has sufficient EC2 permissions.
- If SSH to the instance fails, confirm security group inbound rules include your public IP for port 22.
- If the tunnel fails to establish, check the SSH stderr printed by the script for root causes (network, key permissions, GatewayPorts not set).
- Use `--dry-run` first to confirm planned API calls without making changes.

## License
MIT License. Use at your own risk. This tool is intended for authorized testing and lab use only.

