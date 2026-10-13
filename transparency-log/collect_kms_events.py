#!/usr/bin/env python3
"""
KMS Event Collector

Collects AWS CloudTrail events for KMS key policy changes and IAM role changes.
Records them in a canonical, privacy-respecting format for the transparency log.

Events collected:
- KMS: PutKeyPolicy, CreateGrant, RetireGrant, RevokeGrant, ScheduleKeyDeletion,
  CancelKeyDeletion, DisableKey, EnableKey, CreateKey, CreateAlias, UpdateAlias,
  DeleteAlias, ImportKeyMaterial
- IAM (for room host role): PutRolePolicy, AttachRolePolicy, DetachRolePolicy,
  DeleteRolePolicy, UpdateAssumeRolePolicy

Privacy:
- No personal names
- No IP addresses
- Account-specific identifiers reduced to short hashes
- Only the changed policy content is stored (for PutKeyPolicy)
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


def hash_identifier(identifier: str) -> str:
    """
    Hash an account-specific identifier to a short hash.
    First 8 chars of SHA256 hex for privacy while maintaining uniqueness.
    """
    return hashlib.sha256(identifier.encode('utf-8')).hexdigest()[:8]


def hash_request_parameters(params: Dict[str, Any]) -> str:
    """
    Compute SHA256 of request parameters (canonical JSON).
    """
    json_str = json.dumps(params, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(json_str.encode('utf-8')).hexdigest()


def extract_actor_info(event: Dict[str, Any]) -> Dict[str, str]:
    """
    Extract actor information from CloudTrail event, respecting privacy.
    
    Returns:
        {
            "actor_type": "assumed-role" | "user" | "root" | "service" | "unknown",
            "actor_id_hash": "short hash of account-specific name"
        }
    """
    user_identity = event.get("userIdentity", {})
    identity_type = user_identity.get("type", "unknown")
    
    # Extract account-specific identifier
    principal_id = user_identity.get("principalId", "")
    arn = user_identity.get("arn", "")
    
    # Normalize type (CloudTrail uses PascalCase like "AssumedRole", "IAMUser")
    actor_type = identity_type.lower()
    
    # Map to normalized types
    if actor_type == "assumedrole":
        actor_type = "assumed-role"
    elif actor_type == "iamuser":
        actor_type = "user"
    elif actor_type == "awsservice":
        actor_type = "service"
    elif actor_type not in ["root", "assumed-role", "user", "service"]:
        actor_type = "unknown"
    
    # Hash the principal ID (which contains account-specific info)
    actor_id_hash = hash_identifier(principal_id if principal_id else arn)
    
    return {
        "actor_type": actor_type,
        "actor_id_hash": actor_id_hash
    }


def normalize_event(event: Dict[str, Any], event_category: str) -> Dict[str, Any]:
    """
    Normalize a CloudTrail event to canonical format for transparency log.
    
    Args:
        event: CloudTrail event dict
        event_category: "kms" or "iam"
    
    Returns:
        Normalized record dict
    """
    event_name = event.get("eventName", "Unknown")
    event_time = event.get("eventTime", "")
    event_id = event.get("eventID", "")
    
    # Extract actor info (privacy-respecting)
    actor_info = extract_actor_info(event)
    
    # Extract resource identifier
    resource_id = None
    if event_category == "kms":
        # For KMS, extract key ID from resources
        resources = event.get("resources", [])
        for resource in resources:
            resource_type = resource.get("type", "")
            if resource_type == "AWS::KMS::Key":
                arn = resource.get("ARN", "")
                # Extract key ID from ARN: arn:aws:kms:region:account:key/key-id
                if arn and ":key/" in arn:
                    resource_id = arn.split(":key/")[-1]
                    break
        
        # Fallback: try to get keyId from request parameters
        if not resource_id:
            request_params = event.get("requestParameters") or {}
            key_id = request_params.get("keyId", "")
            if key_id:
                # keyId might be just the UUID or a full ARN
                if ":key/" in key_id:
                    resource_id = key_id.split(":key/")[-1]
                else:
                    resource_id = key_id
    elif event_category == "iam":
        # For IAM, extract role name from request parameters
        request_params = event.get("requestParameters") or {}
        resource_id = request_params.get("roleName", "")
    
    # Hash request parameters
    request_params = event.get("requestParameters") or {}
    params_hash = hash_request_parameters(request_params)
    
    # Extract policy document for PutKeyPolicy (this is what outsiders need to see)
    policy_document = None
    if event_name == "PutKeyPolicy":
        policy_str = request_params.get("policy", "")
        if policy_str:
            try:
                # Parse and re-serialize for canonical form
                policy_obj = json.loads(policy_str)
                policy_document = json.dumps(policy_obj, sort_keys=True, indent=2)
            except json.JSONDecodeError:
                # If parsing fails, store as-is
                policy_document = policy_str
    
    # Build normalized record
    record = {
        "event_time": event_time,
        "event_name": event_name,
        "event_id": event_id,
        "event_category": event_category,
        "resource_id": resource_id,
        "actor_type": actor_info["actor_type"],
        "actor_id_hash": actor_info["actor_id_hash"],
        "request_params_hash": params_hash,
    }
    
    if policy_document:
        record["policy_document"] = policy_document
    
    return record


def collect_cloudtrail_events(
    date: str,
    region: str = "eu-north-1",
    iam_region: str = "us-east-1",
    role_name_filter: Optional[str] = None
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Collect CloudTrail events for KMS and IAM changes on a given date.
    
    Args:
        date: Date in YYYY-MM-DD format
        region: AWS region for KMS events
        iam_region: AWS region for IAM events
        role_name_filter: Optional role name to filter IAM events
    
    Returns:
        {
            "kms_events": [...],
            "iam_events": [...]
        }
    """
    try:
        import boto3
    except ImportError:
        raise ImportError("boto3 is required. Install with: pip install boto3")
    
    # Parse date
    try:
        target_date = datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"Invalid date format: {date}. Expected YYYY-MM-DD")
    
    # CloudTrail query range: 00:00:00 to 23:59:59 UTC
    start_time = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
    end_time = target_date.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    kms_event_names = [
        "PutKeyPolicy",
        "CreateGrant",
        "RetireGrant",
        "RevokeGrant",
        "ScheduleKeyDeletion",
        "CancelKeyDeletion",
        "DisableKey",
        "EnableKey",
        "CreateKey",
        "CreateAlias",
        "UpdateAlias",
        "DeleteAlias",
        "ImportKeyMaterial",
    ]
    
    iam_event_names = [
        "PutRolePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "DeleteRolePolicy",
        "UpdateAssumeRolePolicy",
    ]
    
    kms_events = []
    iam_events = []
    
    # Collect KMS events
    try:
        cloudtrail_kms = boto3.client('cloudtrail', region_name=region)
        
        for event_name in kms_event_names:
            paginator = cloudtrail_kms.get_paginator('lookup_events')
            page_iterator = paginator.paginate(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': event_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )
            
            for page in page_iterator:
                for event in page.get('Events', []):
                    # Parse CloudTrail event JSON
                    event_record = json.loads(event.get('CloudTrailEvent', '{}'))
                    kms_events.append(event_record)
        
    except Exception as e:
        # If credentials are missing or other error, raise
        raise RuntimeError(f"Failed to query KMS CloudTrail events: {e}")
    
    # Collect IAM events (optional, might be expensive)
    try:
        cloudtrail_iam = boto3.client('cloudtrail', region_name=iam_region)
        
        for event_name in iam_event_names:
            paginator = cloudtrail_iam.get_paginator('lookup_events')
            page_iterator = paginator.paginate(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': event_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
            )
            
            for page in page_iterator:
                for event in page.get('Events', []):
                    event_record = json.loads(event.get('CloudTrailEvent', '{}'))
                    
                    # Filter by role name if specified
                    if role_name_filter:
                        request_params = event_record.get('requestParameters', {})
                        role_name = request_params.get('roleName', '')
                        if role_name_filter.lower() not in role_name.lower():
                            continue
                    
                    iam_events.append(event_record)
        
    except Exception as e:
        # IAM events are optional; log but don't fail
        print(f"Warning: Failed to query IAM CloudTrail events: {e}", file=sys.stderr)
    
    return {
        "kms_events": kms_events,
        "iam_events": iam_events
    }


def write_records(
    date: str,
    kms_events: List[Dict[str, Any]],
    iam_events: List[Dict[str, Any]],
    output_dir: Path
) -> None:
    """
    Write normalized event records to output directory.
    
    Directory structure:
        records/<date>/
            kms_<event_id>.json
            iam_<event_id>.json
            summary.json
    """
    # Create date-specific directory
    date_dir = output_dir / date
    date_dir.mkdir(parents=True, exist_ok=True)
    
    # Normalize and write KMS events
    for event in kms_events:
        normalized = normalize_event(event, "kms")
        event_id = normalized["event_id"]
        
        filename = f"kms_{event_id}.json"
        filepath = date_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(normalized, f, indent=2, sort_keys=True)
            f.write('\n')
    
    # Normalize and write IAM events
    for event in iam_events:
        normalized = normalize_event(event, "iam")
        event_id = normalized["event_id"]
        
        filename = f"iam_{event_id}.json"
        filepath = date_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(normalized, f, indent=2, sort_keys=True)
            f.write('\n')
    
    # Write summary
    summary = {
        "date": date,
        "kms_event_count": len(kms_events),
        "iam_event_count": len(iam_events),
        "total_event_count": len(kms_events) + len(iam_events),
        "collected_at": datetime.utcnow().isoformat() + "Z"
    }
    
    summary_path = date_dir / "summary.json"
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write('\n')


def write_not_connected_record(date: str, output_dir: Path) -> None:
    """
    Write a 'not connected' record when AWS credentials are not available.
    This ensures the log shows a clear signal rather than failing silently.
    """
    date_dir = output_dir / date
    date_dir.mkdir(parents=True, exist_ok=True)
    
    not_connected = {
        "date": date,
        "status": "kms_feed_not_connected",
        "message": "AWS credentials not configured. KMS event collection is not available.",
        "collected_at": datetime.utcnow().isoformat() + "Z"
    }
    
    filepath = date_dir / "not_connected.json"
    with open(filepath, 'w') as f:
        json.dump(not_connected, f, indent=2, sort_keys=True)
        f.write('\n')


def main():
    parser = argparse.ArgumentParser(
        description="Collect AWS CloudTrail events for KMS and IAM changes"
    )
    parser.add_argument(
        "--date",
        required=True,
        help="Date to collect events for (YYYY-MM-DD)"
    )
    parser.add_argument(
        "--output-dir",
        default="records",
        help="Output directory for records (default: records/)"
    )
    parser.add_argument(
        "--kms-region",
        default="eu-north-1",
        help="AWS region for KMS events (default: eu-north-1)"
    )
    parser.add_argument(
        "--iam-region",
        default="us-east-1",
        help="AWS region for IAM events (default: us-east-1)"
    )
    parser.add_argument(
        "--role-name-filter",
        help="Optional: filter IAM events by role name (case-insensitive substring match)"
    )
    parser.add_argument(
        "--allow-not-connected",
        action="store_true",
        help="If AWS credentials are not available, write 'not connected' record instead of failing"
    )
    
    args = parser.parse_args()
    
    output_dir = Path(args.output_dir)
    
    # Try to collect events
    try:
        print(f"Collecting CloudTrail events for {args.date}...")
        print(f"  KMS region: {args.kms_region}")
        print(f"  IAM region: {args.iam_region}")
        if args.role_name_filter:
            print(f"  IAM role filter: {args.role_name_filter}")
        
        result = collect_cloudtrail_events(
            date=args.date,
            region=args.kms_region,
            iam_region=args.iam_region,
            role_name_filter=args.role_name_filter
        )
        
        kms_events = result["kms_events"]
        iam_events = result["iam_events"]
        
        print(f"Found {len(kms_events)} KMS events")
        print(f"Found {len(iam_events)} IAM events")
        
        # Write records
        write_records(args.date, kms_events, iam_events, output_dir)
        
        print(f"✅ Successfully collected and wrote {len(kms_events) + len(iam_events)} events to {output_dir}/{args.date}/")
        
        return 0
        
    except (ImportError, RuntimeError) as e:
        if args.allow_not_connected:
            print(f"⚠️  {e}", file=sys.stderr)
            print(f"Writing 'not connected' record...", file=sys.stderr)
            write_not_connected_record(args.date, output_dir)
            print(f"✅ Wrote 'not connected' record to {output_dir}/{args.date}/")
            return 0
        else:
            print(f"❌ Error: {e}", file=sys.stderr)
            print(f"Use --allow-not-connected to write 'not connected' record instead of failing", file=sys.stderr)
            return 1


if __name__ == "__main__":
    sys.exit(main())
