import boto3
import botocore.exceptions
import argparse
import json
import sys
import os
import random
import string
from configparser import ConfigParser
from termcolor import cprint
from datetime import datetime

def get_session(profile):
    try:
        return boto3.Session(profile_name=profile)
    except Exception as e:
        cprint(f'Error creating session with profile {profile}:\n{e}', 'red')
        sys.exit(1)

def authenticate_user(session):
    try:
        client = session.client('sts')
        response = client.get_caller_identity()
        cprint('Authenticated!\n', 'green')
        return response['Arn'], response['Account']
    except Exception as e:
        cprint(f'Error authenticating user:\n{e}', 'red')
        sys.exit(1)

def get_permissive_roles(session, user_arn):
    client = session.client('iam')
    roles = []
    try:
        for page in client.get_paginator('list_roles').paginate():
            roles.extend(page['Roles'])
        permissive_roles = []
        for role in roles:
            if get_role_permission(role['AssumeRolePolicyDocument'], user_arn):
                permissive_roles.append({
                    'RoleName': role['RoleName'],
                    'RoleArn': role['Arn']
                })
        return permissive_roles
    except botocore.exceptions.ClientError as e:
        cprint(f"Access Denied or Unexpected error: {e.response['Error']['Message']}", "red")
        sys.exit(1)

def get_role_permission(policy_document, user_arn):
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') == 'Allow' and 'Principal' in statement:
            principal_arns = statement['Principal'].get('AWS', [])
            if isinstance(principal_arns, str):
                principal_arns = [principal_arns]
            if user_arn in principal_arns:
                return True
    return False

def role_chaining_check(session, permissive_roles):
    """Check each permissive role for possible role chains and output chaining details."""
    role_chaining_found = False
    chainable_roles = []

    for role in permissive_roles:
        role_name = role['RoleName']
        role_arn = role['RoleArn']
        
        assumable_roles = check_policies_for_chaining(session, role_name, role_arn)
        if assumable_roles:
            chainable_roles.append({
                'RoleName': role_name,
                'AssumableRoles': assumable_roles
            })
            role_chaining_found = True

    if not role_chaining_found:
        cprint("No roles found that allow chaining.", "red")
    else:
        cprint("Roles that allow chaining:", "green")
        for role in chainable_roles:
            print(f" - Role Name: {role['RoleName']}")
            for assumable_role in role['AssumableRoles']:
                print(f"   -> Can assume: {assumable_role}")

def check_policies_for_chaining(session, role_name, role_arn):
    """Check both inline and managed policies for sts:AssumeRole permissions."""
    client = session.client('iam')
    assumable_roles = []
    for policy_type, paginator, policy_fetcher in [
        ('inline', client.get_paginator('list_role_policies'), get_role_policy),
        ('managed', client.get_paginator('list_attached_role_policies'), get_managed_policy)
    ]:
        for page in paginator.paginate(RoleName=role_name):
            for policy in page.get('PolicyNames', []) + page.get('AttachedPolicies', []):
                policy_document = policy_fetcher(session, role_name, policy)
                assumable_roles += extract_assumable_roles(policy_document)
    return assumable_roles

def extract_assumable_roles(policy_document):
    """Extract roles that can be assumed from a policy document."""
    assumable_roles = []
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') == 'Allow' and 'sts:AssumeRole' in statement.get('Action', []):
            resource_arns = statement.get('Resource', [])
            if isinstance(resource_arns, str):
                resource_arns = [resource_arns]
            for resource_arn in resource_arns:
                if ":role/" in resource_arn:
                    role_name = resource_arn.split(":role/")[-1]
                    assumable_roles.append(role_name)
    return assumable_roles

def get_role_policy(session, role_name, policy_name):
    client = session.client('iam')
    return client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']

def get_managed_policy(session, role_name, policy):
    client = session.client('iam')
    policy_arn = policy['PolicyArn']
    policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    return client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

def assume_user_role(session, role_name, role_arn, profile_name):
    """Assumes the role and saves credentials to the specified profile name."""
    client = session.client('sts')
    try:
        assumed_role_object = client.assume_role(
            RoleArn=role_arn,
            RoleSessionName=role_name,
            DurationSeconds=3600
        )
        role_creds = assumed_role_object['Credentials']
        
        # Write the credentials to the specified profile
        aws_credentials_path = os.path.expanduser("~/.aws/credentials")
        config = ConfigParser()
        config.read(aws_credentials_path)
        config[profile_name] = {
            "aws_access_key_id": role_creds['AccessKeyId'],
            "aws_secret_access_key": role_creds['SecretAccessKey'],
            "aws_session_token": role_creds['SessionToken']
        }
        with open(aws_credentials_path, 'w') as configfile:
            config.write(configfile)
        
        cprint(f"Temporary credentials saved to profile '{profile_name}'", "green")
        return profile_name
    except Exception as e:
        cprint(f'Error assuming role {role_name}:\n{e}', 'red')
        return None

def main() -> None:
    parser = argparse.ArgumentParser(description="AWS Role Chaining Tool")
    parser.add_argument(
        "-m",
        "--mode",
        choices=["discovery", "automated"],
        required=True,
        help="Mode of operation: 'discovery' to find permissive roles or 'automated' for role chaining.",
    )
    parser.add_argument("-p", "--profile", default="default", help="AWS profile to use (for discovery mode only).")
    parser.add_argument("-r", "--role", help="Role name for chaining (required for automated mode).")
    args = parser.parse_args()

    session = get_session(args.profile)
    user_arn, account_id = authenticate_user(session)

    if args.mode == "discovery":
        permissive_roles = get_permissive_roles(session, user_arn)
        role_chaining_check(session, permissive_roles)
    
    elif args.mode == "automated":
        if not args.role:
            parser.error("the following argument is required for automated mode: -r/--role")
        
        role_arn = f"arn:aws:iam::{account_id}:role/{args.role}"
        profile_name = "RoleChainProfile_" + ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        
        result_profile = assume_user_role(session, args.role, role_arn, profile_name)
        if result_profile:
            print(f"You can now use the profile with AWS CLI by specifying --profile {result_profile}")

if __name__ == "__main__":
    main()
