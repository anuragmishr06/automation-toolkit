#!/bin/bash

TARGET_IP="IP-Address"
REGION="us-east-1"

while true; do
    # Allocate an Elastic IP
    ALLOC_JSON=$(aws ec2 allocate-address --domain vpc --region $REGION)
    ALLOC_IP=$(echo $ALLOC_JSON | jq -r '.PublicIp')
    ALLOC_ID=$(echo $ALLOC_JSON | jq -r '.AllocationId')

    echo "Got IP: $ALLOC_IP"

    if [ "$ALLOC_IP" == "$TARGET_IP" ]; then
        echo "🎯 Got target IP: $ALLOC_IP"
        exit 0
    else
        # Release if not target
        aws ec2 release-address --allocation-id $ALLOC_ID --region $REGION
    fi
done
