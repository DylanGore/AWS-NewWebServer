from config import instance_data
from utils import usr_log


def check_for_iam_instance_profile(iam):
    """
    Check to see if the Instance Profile created by this
    script exists

    Parameters:
        iam: the IAM variable 
    """
    try:
        inst_profile = iam.InstanceProfile(instance_data['role'])
        # Attmept to load the instance profile to check if it exist
        inst_profile.load()
        usr_log(f"IAM: Got Instance Profile: {inst_profile}", "success")
        return inst_profile
    except Exception as error:
        usr_log(f"IAM: Unable to find instance profile - {error}", "error")
        return create_iam_instance_profile(iam)


def create_iam_instance_profile(iam):
    """
    Create an IAM instance profile to allow the instance to push metrics to CloudWatch

    Parameters:
        iam: the IAM variable 
    """
    try:
        inst_profile = iam.create_instance_profile(InstanceProfileName=instance_data['role'])
        usr_log(f'IAM: Created Instance Profile: {inst_profile}', 'info')
        return inst_profile
    except Exception as error:
        usr_log(f'IAM: Error creating instance profile: {error}', 'error')
        return None


def check_for_iam_role(iam, sts_client):
    """
    Check to see if the IAM role created by this script exists

    Parameters:
        iam: the IAM variable
        sts_client: the Security Token Service (STS) variable 
    """
    try:
        role = iam.Role(instance_data['role'])
        # Attmept to load role to check if it exist
        role.reload()
        usr_log(f"IAM: Got Role: {role}", "success")
        return role
    except Exception as error:
        usr_log(f"IAM: Unable to find role - {error}", "error")
        return create_iam_role(iam, sts_client)


def create_iam_role(iam, sts_client):
    """
    Create an IAM role to allow the instance to push metrics to CloudWatch

    Parameters:
        iam: the IAM variable
        sts_client: the Security Token Service (STS) variable 
    """
    try:
        role = iam.create_role(
            RoleName=instance_data['role'],
            AssumeRolePolicyDocument='''{
				"Version": "2012-10-17",
				"Statement": [
					{
					"Sid": "",
					"Effect": "Allow",
					"Principal": {
						"Service": "ec2.amazonaws.com"
					},
					"Action": "sts:AssumeRole"
					}
				]
			}''',
            Description='DevOps Assignment 1 (Dylan Gore) - Allows write access to CloudWatch for custom metrics',
            Tags=[{'Key': 'Type', 'Value': instance_data['type']}]
        )
        usr_log(f"IAM: Created Role: {role}", "success")

        # Attach IAM policy
        try:
            response = role.attach_policy(PolicyArn=check_for_iam_policy(iam, sts_client).arn)
            usr_log(f'IAM: Attached policy to role', 'info')
            usr_log(response, 'debug')
        except Exception as error:
            usr_log(f"IAM: Failed to attach policy to role - {error}", "error")

        # Attach IAM instance profile
        try:
            inst_profile = check_for_iam_instance_profile(iam)
            response = inst_profile.add_role(RoleName=instance_data['role'])
            usr_log(f'IAM: Attached instance profile to role', 'info')
            usr_log(response, 'debug')
        except Exception as error:
            usr_log(f"IAM: Failed to attach instance policy to role - {error}", "error")

        return role

    except Exception as error:
        usr_log(f"IAM: Failed to create role - {error}", "error")
        return None


def check_for_iam_policy(iam, sts_client):
    """
    Check to see if the IAM policy created by this script exists

    Parameters:
        iam: the IAM variable
        sts_client: the Security Token Service (STS) variable 
    """

    # Get the policy ARN
    policy_name = instance_data['role']
    account_id = sts_client.get_caller_identity()['Account']
    usr_log(f"ACCOUNT ID: {account_id}", "debug")
    policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'

    try:
        policy = iam.Policy(policy_arn)
        # Attmept to load policy to check if it exist
        policy.load()
        usr_log(f"IAM: Got Metric Policy: {policy}", "success")
        return policy
    except Exception as error:
        usr_log(f"IAM: Failed to get metric policy - {error}", "error")
        return create_iam_policy(iam)


def create_iam_policy(iam):
    """
    Create an IAM policy to allow the instance to push metrics to CloudWatch

    Parameters:
        iam: the IAM variable 
    """
    try:
        policy = iam.create_policy(
            PolicyName=instance_data['role'],
            PolicyDocument='''{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Sid": "VisualEditor0",
						"Effect": "Allow",
						"Action": "cloudwatch:PutMetricData",
						"Resource": "*"
					}
				]
			}''',
            Description='DevOps Assignment 1 (Dylan Gore) - Allows write access to CloudWatch for custom metrics'
        )

        usr_log(f'IAM: Created policy: {policy}', 'info')
        return policy
    except Exception as error:
        usr_log(f'IAM: Error creating policy: {error}', 'error')
