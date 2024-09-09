import boto3
import botocore.exceptions
import argparse
import json
import sys
from termcolor import cprint
from datetime import datetime

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='AWS Role Chaining Tool')
    parser.add_argument('-p', '--profile', default="default", metavar='profile', type=str, required=False, help='Specify an AWS profile')
    return parser.parse_args()

def get_session(profile):
    """Initialize a boto3 session."""
    try:
        return boto3.Session(profile_name=profile)
    except Exception as e:
        cprint(f'Error creating session with profile {profile}:\n{e}', 'red')
        sys.exit(1)

def authenticate_user(session):
    """Authenticate the user and return their ARN."""
    try:
        client = session.client('sts')
        response = client.get_caller_identity()
        cprint('Authenticated!\n', 'green')
        return response['Arn']
    except Exception as e:
        cprint(f'Error authenticating user:\n{e}', 'red')
        sys.exit(1)

def get_permisive_roles(session, user_arn):
    """Check if the given user has permission on a given role."""
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
    """Helper to get_permisive_roles function, help parse the document policy."""
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') == 'Allow' and 'Principal' in statement:
            principal_arns = statement['Principal'].get('AWS', [])
            if isinstance(principal_arns, str):
                principal_arns = [principal_arns]
            if user_arn in principal_arns:
                return True
    return False

def role_chaning_check(session, permisive_roles):
    """For each permisive role, check both inline and managed policies to see if the role allows assuming another role."""
    client = session.client('iam')
    role_chaining_found = False
    assumable_roles = []  # List to store all roles allowing role chaining

    for role in permisive_roles:
        role_name = role['RoleName']
        role_arn = role['RoleArn']

        if check_policies(session, role_name, role_arn, client.get_paginator('list_role_policies'), get_role_policy) or \
           check_policies(session, role_name, role_arn, client.get_paginator('list_attached_role_policies'), get_managed_policy):
            creds = assume_user_role(session, role_name, role_arn)
            if creds:
                assumable_roles.append(role_name)
                role_chaining_found = True
                cprint(f"Assumed role credentials from '{role_name}' role:", "green")
                print(json.dumps(creds, default=convert_datetime, indent=2))

    if not role_chaining_found:
        cprint("No roles found that allow chaining.", "red")
    else:
        cprint(f"Roles that allow chaining: {', '.join(assumable_roles)}", "green")

def check_policies(session, role_name, role_arn, paginator, policy_fetcher):
    """Helper function to determine whether the policy (of each permisive role) is managed or inline."""
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
    """Helper function for check_policies function, returning the role policies of inline policies."""
    client = session.client('iam')
    return client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']

def get_managed_policy(session, role_name, policy):
    """Helper function for check_policies function, returning the role policies of managed policies."""
    client = session.client('iam')
    policy_arn = policy['PolicyArn']
    policy_version = client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    return client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)['PolicyVersion']['Document']

def policy_allows_assume_role(policy_document):
    """Helper function for check_policies function, Check if a policy document allows assuming a role."""
    for statement in policy_document.get('Statement', []):
        if statement.get('Effect') == 'Allow' and 'sts:AssumeRole' in statement.get('Action', []):
            return True
    return False

def assume_user_role(session, role_name, role_arn):
    """Assume the specified role and return temporary credentials."""
    client = session.client('sts')
    try:
        assumed_role_object = client.assume_role(RoleArn=role_arn, RoleSessionName=role_name, DurationSeconds=3600)
        return assumed_role_object['Credentials']
    except Exception as e:
        cprint(f'Error assuming role {role_name}:\n{e}', 'red')
        return None

def convert_datetime(obj):
    """Convert datetime objects to string for JSON serialization."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")

def main():
    args = parse_arguments()
    session = get_session(args.profile)
    user_arn = authenticate_user(session)
    permisive_roles = get_permisive_roles(session, user_arn)
    role_chaning_check(session, permisive_roles)

if __name__ == '__main__':
    main()
