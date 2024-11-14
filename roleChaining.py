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

def get_permisive_roles(session, user_arn):
    client = session.client('iam')
    roles = []
    try:
        for page in client.get_paginator('list_roles').paginate():
            roles.extend(page['Roles'])
        permisive_roles = [
            {
                'RoleName': role['RoleName'],
                'RoleArn': role['Arn']
            }
            for role in roles
            if get_role_permission(role['AssumeRolePolicyDocument'], user_arn)
        ]
        return permisive_roles
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            cprint(f"Access Denied: {e.response['Error']['Message']}", "red")
            sys.exit(1)
        else:
            cprint(f"An unexpected error occurred: {e.response['Error']['Message']}", "red")
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

def role_chaning_check(session, permisive_roles, mode, return_profile_name):
    client = session.client('iam')
    role_chaining_found = False
    assumable_roles = []

    for role in permisive_roles:
        role_name = role['RoleName']
        role_arn = role['RoleArn']

        if check_policies(session, role_name, role_arn, client.get_paginator('list_role_policies'), get_role_policy) or \
           check_policies(session, role_name, role_arn, client.get_paginator('list_attached_role_policies'), get_managed_policy):
            role_chain_creds = assume_user_role(session, role_name, role_arn, mode, return_profile_name)
            if role_chain_creds:
                assumable_roles.append(role_name)
                role_chaining_found = True
                cprint(f"Assumed role credentials from '{role_name}' role:", "green")
            return role_chain_creds

    if not role_chaining_found:
        cprint("No roles found that allow chaining.", "red")
    else:
        cprint(f"Roles that allow chaining: {', '.join(assumable_roles)}", "green")

def check_policies(session, role_name, role_arn, paginator, policy_fetcher):
    role_allows_assume_role = False
    for page in paginator.paginate(RoleName=role_name):
        for policy in page.get('PolicyNames', []) + page.get('AttachedPolicies', []):
            policy_document = policy_fetcher(session, role_name, policy)
            if policy_allows_assume_role(policy_document):
                policy_type = 'inline' if 'PolicyName' in policy else 'managed'
                policy_name = policy if isinstance(policy, str) else policy['PolicyName']
                cprint(f"{policy_type.capitalize()} policy '{policy_name}' in role '{role_name}' allows assuming another role.", "green")
                role_allows_assume_role = True
    return role_allows_assume_role

def get_role_policy(session, role_name, policy_name):
    client = session.client('iam')
    return client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']

def get_managed_policy(session, role_name, policy):
    client = session.client('iam')
    policy_arn = policy['PolicyArn']
    policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    return client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

def policy_allows_assume_role(policy_document):
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') == 'Allow' and 'sts:AssumeRole' in statement.get('Action', []):
            return True
    return False

def assume_user_role(session, role_name, role_arn, mode, return_profile_name):
    client = session.client('sts')
    try:
        assumed_role_object = client.assume_role(RoleArn=role_arn, RoleSessionName=role_name, DurationSeconds=3600)
        role_creds = assumed_role_object['Credentials']
        if mode == "automated":
            aws_credentials_path = os.path.expanduser("~/.aws/credentials")
            config = ConfigParser()
            config.read(aws_credentials_path)
            config[return_profile_name] = {
            "aws_access_key_id": role_creds['AccessKeyId'],
            "aws_secret_access_key": role_creds['SecretAccessKey'],
            "aws_session_token": role_creds['SessionToken']
        }
            with open(aws_credentials_path, 'w') as configfile:
                config.write(configfile)
            cprint(f"Temporary credentials saved to profile '{return_profile_name}'", "green")
            return return_profile_name
        else:
            return role_creds
    except Exception as e:
        cprint(f'Error assuming role {role_name}:\n{e}', 'red')
        return None

def convert_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")

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
    parser.add_argument("-r", "--role", help="Role ARN for chaining (required for automated mode).")
    args = parser.parse_args()

    session = get_session(args.profile)
    user_arn, account_id = authenticate_user(session)
    name_prefix = "RoleChainProfile"
    random_suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return_profile_name = name_prefix + "_" + random_suffix
 
    if args.mode == "automated" and not args.role:
        parser.error("the following argument is required for automated mode: -r/--role")

    if args.mode == "discovery":
        permisive_roles = get_permisive_roles(session, user_arn)
        role_chain_creds = role_chaning_check(session, permisive_roles, args.mode, return_profile_name)
        print(json.dumps(role_chain_creds, default=convert_datetime, indent=2))
    
    elif args.mode == "automated":
        role_arn = f"arn:aws:iam::{account_id}:role/{args.role}"
        assume_user_role(session, args.role, role_arn, args.mode, return_profile_name)

if __name__ == "__main__":
    main()
