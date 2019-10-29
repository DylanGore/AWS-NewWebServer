# Variables
use_existing = False  # Weather or not to use an existing EC2 instance or create a new one
info_filename = 'aws-info.txt'  # File name for local information file
img_name = 'image.jpg'  # File name for the image to display
key_prefix = 'devops-'  # Prefix to be added to SSH keys
bucket_name_prefix = 'dylangore-wit-devops'  # Prefix to attach to all bucket names
sg_description = 'Boto3 Created SG'  # Description to attach to all security groups

# Default bucket information
bucket_info = {
    'name': bucket_name_prefix,
    'region': 'eu-west-1'
}

# Default instance information
instance_data = {
    'name': 'Assignment1-WebServer',
    'key_name': 'devops-DylanGore-WIT2019',
    'ami': 'ami-0ce71448843cb18a1',
    'sg_id': 'sg-0bdfc8ad0a7d7a2df',
    'role': 'DevOps_PutMetricData',
    'type': 'DevOps-AWS-Assignment1',
    'region': 'eu-west-1'
}

# Filters out instances that are running and were created by this script
running_filters = [
    {
        'Name': 'instance-state-name',
        'Values': ['running']
    },
    {
        'Name': 'tag:Type',
        'Values': [instance_data['type']]
    }
]

# User data script to run on instance creation
user_data = '''#!/bin/bash
yum update -y
yum upgrade -y
yum install python3-pip -y
pip3 install boto3
pip3 install requests
yum install httpd -y
systemctl enable httpd
systemctl start httpd
echo -e '<Location /server-status>\n\tSetHandler server-status\n\tOrder deny,allow\n\tDeny from all\n\tAllow from 127.0.0.1\n</Location>' > /etc/httpd/conf.d/status.conf
systemctl restart httpd
'''


def set_debug_mode(value):
    """
    Function to set debug mode value for use in all files

    Parameters:
        - value: the value to set debug_mode to
    """
    global debug_mode
    debug_mode = value


def get_debug_mode():
    """
    Function to get debug mode value for use in all files

    Returns:
        debug_mode - boolean for debug mode being on or off
    """
    return debug_mode
