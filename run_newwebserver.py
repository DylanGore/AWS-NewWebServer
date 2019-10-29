#!/usr/bin/env python3

import boto3
import subprocess
import logging
import paramiko
import requests
import argparse
from bs4 import BeautifulSoup
from os import remove, path
from time import sleep
from datetime import datetime, timedelta, timezone
from consolemenu import ConsoleMenu
from consolemenu.items import FunctionItem, SubmenuItem, CommandItem
from colorama import init, Fore

# Local imports
from utils import *
from config import *
from iam import check_for_iam_role, check_for_iam_instance_profile, check_for_iam_policy

# Initialise Colorama
init(autoreset=True)

# SSH Basic Configuration
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Answer yes to strict host key check prompt


def init_script():
    """
    Initialises AWs boto3 variables assuming that the AWS credentials
    are present and correct, if not, run 'aws configure' to allow the
    user to set them up
    """

    global ec2
    global s3
    global iam
    global sts_client
    global cw
    global cw_client

    usr_log('Loading script...', 'info')

    # Ensure AWS credentials are set
    check_aws_credentials()

    # Initialize AWS service variables
    ec2 = boto3.resource("ec2", instance_data['region'])
    s3 = boto3.resource("s3", instance_data['region'])
    iam = boto3.resource('iam')
    sts_client = boto3.client('sts')
    cw = boto3.resource('cloudwatch', instance_data['region'])
    cw_client = boto3.client('cloudwatch', instance_data['region'])

    # Handle Command Line Args
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", "-in", help="The name of the instance that will be created")
    parser.add_argument("--auto", "-a", help="Create a new EC2 instance using default values", action="store_true")
    parser.add_argument("--debug", "-d", help="Enable debug mode", action="store_true")
    args = parser.parse_args()

    # --debug flag
    if args.debug:
        usr_log("CLI Args: Enable debug mode", "info")
        set_debug_mode(True)
    else:
        set_debug_mode(False)

    usr_log(f"Debug Mode: {str(get_debug_mode())}", 'info')

    # --auto flag
    if args.auto:
        usr_log("CLI Args: Creating instance using default values")
        full_run()

    # --name flag
    elif args.name:
        usr_log(
            f"CLI Args Found: Automatically creating instance \nInstanceName: {args.name}\nKeyName: {args.key}", "info")
        instance_name = args.name

        full_run(instance_name=instance_name)

        input("Press enter to continue...")


def main():
    """
    Run the intial setup script, check for an input file and show the main menu
    """

    init_script()
    read_info_file()

    # Define Menu
    menu = ConsoleMenu(
        title="AWS EC2 and S3 Webserver Configuration Script",
        subtitle="Developer Operations Assignment 1 - Dylan Gore",
    )

    # Define menu options and what they do
    opt_full_run = FunctionItem("Run automatic configuration", wait_func, [full_run])
    opt_user_input = FunctionItem("Input custom settings", wait_func, [accept_user_input])
    opt_active = FunctionItem("List running instances/active buckets", wait_func, [list_active])
    opt_monitoring = FunctionItem("Display monitoring info", wait_func, [display_monitor])
    # opt_website = FunctionItem("Check if web server is running", wait_func, [check_website])
    # opt_iam = FunctionItem("Create IAM role & policy", wait_func, [check_for_iam_role, iam, sts_client])
    opt_configure_aws = CommandItem("Configure AWS credentials and Settigns", "aws configure")
    opt_load_config_file = FunctionItem("Load configuration file", wait_func, [read_info_file])
    opt_cleanup = FunctionItem("Cleanup AWS", wait_func, [cleanup])
    opt_clear_logs = FunctionItem("Clear logs", wait_func, [clear_logs])

    # Add options to menu
    menu.append_item(opt_full_run)
    menu.append_item(opt_user_input)
    menu.append_item(opt_active)
    menu.append_item(opt_monitoring)
    # menu.append_item(opt_website)
    # menu.append_item(opt_iam)
    menu.append_item(opt_configure_aws)
    menu.append_item(opt_load_config_file)
    menu.append_item(opt_cleanup)
    menu.append_item(opt_clear_logs)

    # Display the menu and wait for user input
    menu.show()

    # Print when user runs the 'Exit' option
    print("Exiting...")


def full_run(instance_name=instance_data['name'], key_name=instance_data['key_name'], sg_id=instance_data['sg_id']):
    """
    Runs everything with default values.
    - Creates a new EC2 instance
    - Creates a new S3 bucket
    - Downloads the image
    - Uploads the image to the bucket and makes it public
    - Opens an SSH connection
    - Creates the remote HTML file and moves it into place
    - Checks that the web server is running
    - Offeres to remove the instance and bucket from AWS
    """
    global instance
    global bucket
    global url
    global info_file

    # Check if the required IAM role and policy exist, create them if not
    check_for_iam_role(iam, sts_client)
    usr_log('Waiting 10 seconds for any IAM changes to propagate to AWS...', 'info')
    sleep(10)

    # Run script
    instance = create_ec2_instance(instance_name, key_name, sg_id)

    # Only continue if the instance was created successfully
    if not instance == None:
        bucket = create_bucket(instance)
        download_image()
        url = upload_to_bucket(img_name)
        open_ssh_connection(instance.public_ip_address, instance.key_name)
        info_file = create_info_file(instance, bucket)
    else:
        usr_log("Error creating instance, bucket will not be created and no upload attempts made!", "error")

    # Only wait for apache to start if creating a new instance and it was created successfully
    if not use_existing and not instance == None:
        usr_log("Waiting for 60 seconds for Apache to start...", "info")
        sleep(60)

    # Only check the web server if the instance exists
    if not instance == None:
        check_website()

    # Close the SSH connection as it is no longer required
    ssh_client.close()

    usr_log("Full run finished", "success")


def accept_user_input():
    """
    Get input from the user on various settings . e.g key, instance name, etc.
    """
    key_exists = True
    usr_log("Please enter your custom settings below, leave prompt empty to use current value", "info")

    # Key Name
    key_name = input_string_format("Key name", instance_data['key_name'])
    # Don't add a prefix to the default key, prefix others
    if not key_name == instance_data['key_name']:
        key_name = key_prefix + key_name

    # Check if key exists and download private key if so
    try:
        ec2.KeyPair(key_name).load()
    except Exception as error:
        usr_log(f'Key Doesn\'t Exist: {error}', 'error')
        key_exists = False

    # Create new key
    if not key_exists:
        try:
            # Create the key pair on AWS
            key_pair = ec2.create_key_pair(KeyName=key_name, DryRun=False)
            # Write private key file
            write_simple_file(f"{key_name}.pem", key_pair.key_material)
            usr_log(f"Created new key and saved to file {key_name}.pem", "success")
            try:
                # Set permissions on key
                subprocess.run(['chmod', '600', f'{key_name}.pem'], check=True)
                usr_log(f"Set {key_name}.pem permissions to 600", "success")
            except Exception as error:
                usr_log(f'Key Permission Error: {error}', 'error')
        except Exception as error:
            usr_log(f'Custom Key Error: {error}', 'error')
            # Use default key if there was any errors
            key_name = instance_data['key_name']

    # Instance Name
    instance_name = input_string_format("Instance name", instance_data['name'])

    # Security Group
    default_sg = user_choice(f"Use default security group {instance_data['sg_id']}")
    if not default_sg:
        try:
            usr_log('Getting VPC info', 'info')
            # Gets default VPC so it only shows relevent groups
            all_vpcs = list(ec2.vpcs.filter(Filters=[{'Name': 'isDefault', 'Values': ['true']}]))
            default_vpc_id = all_vpcs[0].id
            usr_log(f'Default VPC: {default_vpc_id}', 'info')
            usr_log(f'Existing Security Groups in VPC {default_vpc_id}: ', 'info')

            # List all groups in the default VPC that the user can select
            sec_groups = list(ec2.security_groups.filter(Filters=[{'Name': 'vpc-id', 'Values': [default_vpc_id]}]))
            for group in sec_groups:
                usr_log(f'- {group.group_name} ({group.id})', 'info')
            usr_log("Choose one of the above groups or enter 'create' to create a new one", 'info')
            # Get input from the user, entering 'create' or anything longer than 4 chars will create a new SG.
            sg_id = input_string_format('Security Group Id', ec2.SecurityGroup(instance_data['sg_id']).id)
            try:
                # Attempt to load the SG to see if it exists
                sg = ec2.SecurityGroup(sg_id)
                sg.load()
                usr_log(f'Loaded SG {sg.id} successfully!', 'success')
            except Exception as error:
                usr_log(f'SG Error: {error}. Attempting to create SG.')
                # If SG doesn't exist, create a new one
                try:
                    sec_group = ec2.create_security_group(
                        Description=sg_description,
                        GroupName=f'devops-sg-{timestamp}',
                        VpcId=default_vpc_id
                    )
                    usr_log(sec_group, 'debug')
                    usr_log(f'Created SG: {sec_group.group_name} ({sec_group.id})', 'success')
                    # Allow incoming SSH Traffic
                    response = sec_group.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=22, ToPort=22)
                    usr_log(response, 'debug')
                    usr_log(f'Allowed incoming SSH connections', 'success')
                    # Allow incoming HTTP Traffic
                    response = sec_group.authorize_ingress(CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=80, ToPort=80)
                    usr_log(response, 'debug')
                    usr_log(f'Allowed incoming HTTP connections', 'success')
                    # Allow incoming HTTPS Traffic
                    response = sec_group.authorize_ingress(
                        CidrIp='0.0.0.0/0', IpProtocol='tcp', FromPort=443, ToPort=443)
                    usr_log(response, 'debug')
                    usr_log(f'Allowed incoming HTTPS connections', 'success')
                    # Set the secrity group id to the newly created one
                    sg_id = sec_group.id
                except Exception as error:
                    usr_log(f'SG Creation Error: {error}. Using default.', 'error')
                    # Set sg_id to default as defined in config.py
                    sg_id = instance_data['sg_id']
        except Exception as error:
            usr_log(f'SG Error: {error}. Using default SG.', 'error')
            # Set sg_id to default as defined in config.py
            sg_id = instance_data['sg_id']
    else:
        # If the user chooses to use the default SG, set it's ID
        sg_id = instance_data['sg_id']

    # Create with custom info
    usr_log(f"Calling full run, {instance_name}, {key_name}", "debug")
    full_run(instance_name=instance_name, key_name=key_name, sg_id=sg_id)


def list_active():
    """
    List running instances and linked buckets from local file and AWS
    """

    # Get and display an info stored in the local aws-info.txt file if it exists
    print(Fore.YELLOW + "Locally stored info:")
    if(path.exists('aws-info.txt')):
        subprocess.run(['cat', 'aws-info.txt'])
    else:
        usr_log("No running instances", "info")

    # Get and display any running instances and buckets from AWS that match the filter
    print(Fore.YELLOW + "\nInformation loaded from AWS:")
    # Check if matching instance exists - anything with the tag stating that it was created by this script
    instances = list(ec2.instances.filter(Filters=[{'Name': 'tag:Type', 'Values': [instance_data['type']]}]))
    # Loop through and terminate all matching instances and buckets
    if len(instances) > 0:
        for instance in instances:
            try:
                usr_log(f"Instance: {instance.id} ({instance.state['Name']})", "info")
                bucket_name = ""
                # Check if a bucket exists with the instance id as a suffix
                bucket_name = f"{bucket_name_prefix}-{instance.id[2:]}"
                bucket = s3.Bucket(bucket_name)
                usr_log(f"\tBucket: {bucket_name}", "info")
                # Empty bucket, file by file
                for file in bucket.objects.all():
                    try:
                        usr_log(f"\t\tFile: {file.key}", "info")
                    except Exception as error:
                        usr_log(f'File List Error: {error}', "error")
            except Exception as error:
                usr_log(f'List Error: {error}', "error")
    else:
        print(Fore.CYAN + "Nothing found")


def check_aws_credentials():
    """
    Ensure that the .aws folder and credentials and config files are present
    """
    cred_path=path.join(path.expanduser('~'), '.aws/credentials')
    conf_path=path.join(path.expanduser('~'), '.aws/config')

    # Check that the above paths exist and display result
    if(path.exists(cred_path) and path.exists(conf_path)):
        usr_log("AWS credentials and config file present in ~/.aws", "success")
    else:
        usr_log("Issue with AWS credentials!", "error")
        # Ask the user if they would like to run 'aws configure'
        conf_aws=user_choice("Would you like to configure your AWS credentials now")
        if conf_aws:
            try:
                # Run aws-cli configure
                subprocess.run(["aws", "configure"], check = True)
            except Exception as error:
                usr_log(str(error), "error")


def create_ec2_instance(instance_name = instance_data['name'], key_name = instance_data['key_name'], sg_id = instance_data['sg_id']):
    """
    Create a new EC2 instance based on previously defined instance data and user data commands

    Returns:
            inststance - the EC2 instance that was created
    """
    # Log the passed arguments
    usr_log(f"instance: {instance_name}, key: {key_name}, sg: {sg_id}", "debug")
    global use_existing
    # Check if matching instance exists
    running_instances=list(ec2.instances.filter(Filters=running_filters))

    # If there is running instances matching the filter, ask the user if they would like to use that or create
    # a new instance
    if len(running_instances) > 0:
        use_existing=user_choice("An instance is already running on this account, would you like to use it")
        # If the user decides to use the existing instance, get it's id and return the instance object
        if use_existing:
            usr_log("Using existing instance", "info")
            instance=ec2.Instance(running_instances[0].id)
            usr_log(f"Using: {instance.id} | IP: {instance.public_ip_address}", "success")
            return instance

    # If there is no running instances or the user wants to create a new one, create it
    if (len(running_instances) == 0 or use_existing == False):
        usr_log("Creating new instance...", "info")

        # Create the instance
        try:
            new_instance=ec2.create_instances(
                ImageId = instance_data['ami'],
                MinCount = 1,
                MaxCount = 1,
                InstanceType = 't2.micro',
                KeyName = key_name,
                TagSpecifications = [{
                    'ResourceType': 'instance',
                    'Tags': [{
                        'Key': 'Name',
                        'Value': instance_name
                    }]
                }],
                Monitoring = {
                    'Enabled': True
                },
                IamInstanceProfile = {'Name': instance_data['role']},
                SecurityGroupIds = [sg_id],
                UserData = user_data
            )
        except Exception as error:
            usr_log(f"Instance Creation Error: {error}", "error")
            return None

        # Wait until the instance is actually running before continuing
        new_instance[0].wait_until_running()

        # Definne the new instance as 'instance' and reload it to allow tagging
        instance=new_instance[0]
        instance.reload()

        # Tag instance
        type_tag={'Key': 'Type', 'Value': instance_data['type']}
        instance.create_tags(Tags = [type_tag])

        # Display instance info to user and return it
        usr_log(f"Created: {instance.id} | IP: {instance.public_ip_address}", "success")
        return instance


def download_image():
    """
    Download the image, delete image.jpg if it already exists
    """

    # Cleanup
    if(path.exists(img_name)):
        remove(img_name)

    # Download image using curl via subprocess.run()
    usr_log("Downloading image", "info")
    try:
        subprocess.run(["curl", "-O", "http://devops.witdemo.net/image.jpg"], check = True)
    except Exception as error:
        usr_log(f"Error downloading image {error}", "error")


def create_bucket(instance):
    """
    Create a new S3 bucket with the instance id as a prefix to ensure a unique name
    """

    # Append instance id to bucket name
    bucket_info['name']=bucket_name_prefix + "-" + instance.id[2:]

    # If bucket doesn't exist, create it
    if(s3.Bucket(bucket_info['name']).creation_date is None):
        try:
            bucket=s3.create_bucket(Bucket = bucket_info['name'], CreateBucketConfiguration = {
                'LocationConstraint': bucket_info['region']})
            usr_log("Created bucket", "success")
            return bucket
        except Exception as error:
            usr_log(str(error), "error")
    else:
        usr_log("Using existing bucket", "success")
        return s3.Bucket(bucket_info['name'])


def upload_to_bucket(file):
    """
    Upload the image to the bucket
    """
    try:
        # Attempt to upload image to S3
        response=s3.Object(bucket_info['name'], file).put(
            Body = open(file, 'rb'),
            ACL = 'public-read'
        )
        # Check if image upload worked
        if(response['ResponseMetadata']['HTTPStatusCode'] == 200):
            print("\n")
            usr_log("File upload successful!", "success")

            # Location of image on S3
            url=f"https://{bucket_info['name']}.s3-{bucket_info['region']}.amazonaws.com/{file}"

            # Remove local copy of image once upload was successful
            if(path.exists(file)):
                try:
                    remove(file)
                    usr_log(f"Removed {file} from local storage", "info")
                except Exception as error:
                    usr_log(error, "error")
            return url

    except Exception as error:
        usr_log("S3 Upload error", "error")
        usr_log(str(error), "error")


def open_ssh_connection(host, key_name, user = "ec2-user"):
    # Set the SSH key for paramiko to use
    try:
        usr_log(f"Attempting to use key: {key_name}.pem for SSH connection", "info")
        ssh_key=paramiko.RSAKey.from_private_key_file(f"{key_name}.pem")
    except Exception as error:
        usr_log(f"Error setting ssh key, using default: {error}", "error")

        # Attempt to use the default SSH key
        try:
            ssh_key=paramiko.RSAKey.from_private_key_file(f"{instance_data['key_name']}.pem")
        except Exception as error:
            usr_log(f"Default SSH Key missing: {error}", "error")
            usr_log(f"No remote sSH commands will be performed!", "error")
            return

    ssh_connection_count=0
    while ssh_connection_count < 3:
        ssh_connection_count += 1
        try:
            # Attempt SSH connection
            ssh_client.connect(hostname = str(host), username = user, pkey = ssh_key)
            usr_log("SSH connection successful!", "success")
            ssh_connection_count=3

            # Only run if SSH is connected
            create_remote_html()
        except Exception as error:
            usr_log(f'SSH Error: {error}', 'error')
            # Ask user if they would like to keep trying to connect
            if ssh_connection_count == 3:
                choice=user_choice("Would you like to keep trying")
                if(choice):
                    ssh_connection_count=0
            sleep(1)


def create_remote_html():
    """
    Create HTML page, get instance IP Address using SSH and curl and push the result to
    the server
    """
    # Create master HTML code
    usr_log("Generating HTML code", "info")
    soup=BeautifulSoup("<html><head><link rel=\"stylesheet\" href=\"https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0/css/materialize.min.css\"><title>EC2</title><head><body class=\"center-align\"></body></html>", features = "html.parser")

    # Create an image tag and add it to the master HTML code
    usr_log("Adding <img> tag", "info")
    img_tag=soup.new_tag("img", src = f"{url}")  # <img  src="{url} />">
    soup.body.append(img_tag)

    # Get instance metadata - local IPv4 address
    usr_log("Getting instance metadata", "info")
    ip_commands=["curl http://169.254.169.254/latest/meta-data/local-ipv4"]
    instance_ipv4="no local ip"
    for command in ip_commands:
        usr_log(f"Executing {command}", "debug")
        stdin, stdout, stderr=ssh_client.exec_command(command)
        instance_ipv4=stdout.read().decode('utf-8')

    # Create a HTML tag and add it to the master HTML code
    ipv4_tag=soup.new_tag("p")
    ipv4_tag.string=f"Instance Local IPv4 Address: {instance_ipv4}"
    soup.body.append(ipv4_tag)

    usr_log(f"Instance Internal IP: {instance_ipv4} - added to HTML", "info")

    # Upload metric script to instance
    try:
        ftp_client=ssh_client.open_sftp()
        ftp_client.put('metric.py', '/home/ec2-user/metric.py')
        ftp_client.close()
        usr_log(f'SFTP: Uploaded file metric.py', 'success')
    except Exception as error:
        usr_log(f'SFTP: Error uplaoding metric.py file - {error}', 'error')

    # Code to add to cron tab to run metric.py on instance every minute
    cron_line="* * * * * ec2-user python3 /home/ec2-user/metric.py >> /home/ec2-user/cron.log"

    # List of commands to run on the instance via SSH
    commands=[f"echo \'{soup.prettify()}\' > index.html",
                "sudo mkdir -p /var/www/html", "sudo mv 'index.html' '/var/www/html/'",
                f"sudo bash -c \"grep -qxF \'{cron_line}\' /etc/crontab || echo \'{cron_line}\' >> /etc/crontab\"",
                "sudo systemctl restart crond"]

    usr_log("Copying HTML to server and moving to web server root directory", "info")

    # Loop through and run commands on the instance
    for command in commands:
        usr_log(f"Executing {command}", "debug")
        stdin, stdout, stderr = ssh_client.exec_command(command)
        sleep(1)


def check_website():
    """
    Use requests to check if the webserver is online and returning HTTP code 200
    """
    max_attempts = 5
    try:
        # required to see if instance exists
        instance.reload()
        attempt = 0
        # Count user attempts ond offer them to stop or keep trying
        while attempt < max_attempts:
            attempt += 1

            if attempt == max_attempts:
                if user_choice("Would you like to keep trying"):
                    attempt = 0
                else:
                    logging.info("User aborted web server check")
                    break

            try:
                # If webserver response with 200, web server is online
                r = requests.head(f"http://{instance.public_ip_address}/")
                if r.status_code == 200:
                    usr_log("Web server online", "success")
                    attempt = max_attempts
                else:
                    usr_log("Web server offline", "error")
                    print("Trying again in 5 seconds...")
                    sleep(5)
            except Exception as error:
                usr_log("Web Server Error: " + str(error), "error")
                print("Trying again in 5 seconds...")
                sleep(5)
    except NameError as error:
        print("Are you sure there is an instance in use?")
        usr_log(f"{error}", "error")


def read_info_file():
    """
    Read local info file to get the most recently created instance/bucket
    if they are still online (the file will not exist if they are not online)
    """
    global instance
    global bucket

    # Check that the file exists
    if path.exists('aws-info.txt'):
        usr_log("Reading local info file", "info")
        file = open(info_filename, "r")
        # Read the file line by line and store the results in the relevent variables
        # https://stackoverflow.com/questions/12330522/reading-file-without-newlines-in-python
        try:
            info = file.read().splitlines()
            instance = ec2.Instance(info[0])
            usr_log(f"Loaded instance: {instance.id}", "info")
            bucket = s3.Bucket(info[1])
            usr_log(f"Loaded bucket: {bucket.name}", "info")
        except Exception as error:
            usr_log(f"File read error: {error}", "error")
    else:
        usr_log("Info file doesn't exist!", "error")


def display_monitor():
    """
    Display CloudWatch metric values to the user
    """

    # EC2 Metrics
    try:
        print(Fore.YELLOW + f"Average metrics for EC2 instance {instance.id}")
        # If the bucket is under 5 minuutes, raise an exception as the instance won't have any statistics
        if datetime.now(timezone.utc) < instance.launch_time + timedelta(minutes=5):  # https://stackoverflow.com/a/39080237
            raise Exception(
                f"Instance must be at least 5 minutes old to have statistics! (Age: {datetime.now(timezone.utc) - instance.launch_time})")
        log_metric_value("AWS/EC2", "CPUUtilization", "%")
        log_metric_value("AWS/EC2", "NetworkIn", "bytes")
        log_metric_value("AWS/EC2", "NetworkOut", "bytes")
        log_metric_value("WIT_DEVOPS/APACHE", "AccessReq", "requests")

    except Exception as error:
        usr_log(f"{error}", "error")

    # S3 Metrics
    try:
        print(Fore.YELLOW + f"Average metrics for S3 bucket {bucket.name}")
        # If the bucket is under 24 hours old, raise an exception as the bucket won't have any statistics
        if datetime.now(timezone.utc) < bucket.creation_date + timedelta(days = 1):  # https://stackoverflow.com/a/39080237
            raise Exception(
                f"Bucket must be at least 24 hours old to have statistics! (Age: {datetime.now(timezone.utc) - bucket.creation_date})")
        log_metric_value("AWS/S3", "NumberOfObjects", "objects")
    except Exception as error:
        usr_log(f"{error}", "error")


def log_metric_value(service = "AWS/EC2", name = "CPUUtilization", unit = "%"):
    """
    Obtain and log a CloudWatch metric value

    Parameters:
        service - which AWS service to get metrics for
        name - the name of the metric
        unit - the unit of measurement for the specified metric
    """
    try:
        # EC2 Metric Settings
        if service == "AWS/EC2":
            cw_dimensions=[{'Name': 'InstanceId', 'Value': instance.id}]
            start_time=datetime.now(timezone.utc) - timedelta(minutes = 5)  # 5 mins ago
            time_period=300  # every 5 minutes
            stats='Average'

        # S3 Metric Settings
        elif service == "AWS/S3":
            cw_dimensions=[{'Name': 'BucketName', 'Value': bucket.name},
                             {'Name': 'StorageType', 'Value': 'AllStorageTypes'}]
            start_time = datetime.now(timezone.utc) - timedelta(days=1)  # 1 day ago
            time_period = 3600  # every hour
            stats = 'Sum'

        # Custom Apache Metric Settings
        elif service == "WIT_DEVOPS/APACHE":
            cw_dimensions = [{'Name': 'Instance', 'Value': str(instance.id)}]
            start_time = datetime.now(timezone.utc) - timedelta(minutes=5)  # 5 mins ago
            time_period = 60  # every minute
            stats = 'Sum'

        # Get metric from CloudWatch and log
        response = cw_client.get_metric_statistics(
            Namespace=service,
            MetricName=str(name),
            Dimensions=cw_dimensions,
            StartTime=start_time,
            EndTime=datetime.now(timezone.utc),
            Period=time_period,
            Statistics=[stats]
        )
        usr_log(response, "debug")
        # Log metric if it exists
        if len(response['Datapoints']) > 0:
            usr_log(f"- {name}: {response['Datapoints'][0][stats]} {unit}", "info")
        else:
            usr_log(f"- {name}: No data available", "info")
    except Exception as error:
        usr_log(f"CloudWatch Error: {error}", "error")


def cleanup():
    """
    Remove any instances or buckets created by this script from AWS
    """
    do_clean = user_choice("Do you want to remove any instance or bucket created by this script from AWS")
    if(do_clean):
        # Check if matching instance exists
        instances = ec2.instances.filter(Filters=running_filters)

        # Loop through and terminate all matching instances and empty linked buckets
        for instance in instances:
            try:
                # Terminate the instance and log the response as a debug message
                response = instance.terminate()
                usr_log(f"Terminated instance {instance.id}", "success")
                usr_log(response, 'debug')
                bucket_name = ""
                try:
                    # See if a bucket exists with the terminated instance ID as a suffix (excluding the 'i-' at the start)
                    bucket_name = f"{bucket_name_prefix}-{instance.id[2:]}"
                    bucket = s3.Bucket(bucket_name)
                    bucket.load()
                    # Empty bucket, delete each file one by one
                    for file in bucket.objects.all():
                        try:
                            file.delete()
                            usr_log(f"Deleted file {file.key}", "info")
                        except Exception as error:
                            usr_log(str(error), "error")
                    try:
                        # Delete the bucket and log the response as a debug message
                        response = bucket.delete()
                        usr_log(f"Removed bucket: {bucket.name}", "success")
                        usr_log(response, 'debug')
                    except Exception as error:
                        usr_log(str(error), "error")
                except Exception as error:
                    usr_log(f"Error deleting {bucket_name}: {error}", "error")

            except Exception as error:
                usr_log(f"Issue terminating {instance.id}: {error}", "error")

        # Delete info file if it exists
        try:
            if(path.exists(info_filename)):
                remove(info_filename)
        except Exception as error:
            usr_log(str(error), "error")

        usr_log("Complete. List of removed items above (if empty nothing was there to delete)", "success")

        # Remove key pairs
        do_remove_keys = user_choice("Do you want to remove any Key Pairs created by this script (excl. default)")
        if do_remove_keys:
            try:
                # Get a list of all key paris on AWS
                for pair in ec2.key_pairs.all():
                    # Check if the key has the correct prefix
                    if pair.name[:7] == key_prefix:
                        # If the key is not the defauly one defined in config.py, delete it
                        if not pair.name == instance_data['key_name']:
                            usr_log(f'Deleting AWS public key: {pair.name}', 'info')
                            # Delete the local private key, delete the public key from AWS and log the response
                            if path.exists(f'{pair.name}.pem'):
                                usr_log(f'Deleting local priavte key: {pair.name}.pem', 'info')
                                remove(f'{pair.name}.pem')
                            response = pair.delete()
            except Exception as error:
                usr_log(f'Error removing key pairs: {error}', 'error')

            usr_log("Complete. List of removed keys above (if empty nothing was there to delete)", "success")

        # Remove IAM role and policy
        try:
            # Check that the IAM role exists before asking the user to delete it
            iam.Role(instance_data['role']).load()
            do_remove_iam = user_choice("Do you want to remove any IAM roles/policies created by this script")
        except:
            usr_log('No IAM role found', 'info')
            # Don't run the delete code if there's no role to delete
            do_remove_iam = False

        if do_remove_iam:
            # Detach and remove IAM policy
            try:
                usr_log('Detaching policy from role', 'info')
                # Get the IAM policy to delete
                del_policy = check_for_iam_policy(iam, sts_client)
                # Detach the policy from the role and log the response as a debug message
                response = del_policy.detach_role(RoleName=instance_data['role'])
                usr_log(response, 'debug')
                usr_log('Deleting IAM policy', 'info')
                # Delete the IAM policy and log the response as a debug message
                response = del_policy.delete()
                usr_log(response, 'debug')
            except Exception as error:
                usr_log(f'Cleanup: Issue removing IAM policy {del_policy}: {error}', 'error')

            # Instance profile
            try:
                usr_log('Detaching instance profile from role', 'info')
                # Get the instance profile to delete
                del_profile = check_for_iam_instance_profile(iam)
                # Delete the IAM role and log the response as a debug message
                response = del_profile.remove_role(RoleName=instance_data['role'])
                usr_log(response, 'debug')
                usr_log('Deleting IAM instance profile', 'info')
                # Delete the instance profile and log the response as a debug message
                response = del_profile.delete()
                usr_log(response, 'debug')
            except Exception as error:
                usr_log(f'Cleanup: Issue removing IAM instance {del_profile}: {error}', 'error')

            try:
                usr_log('Deleting IAM role', 'info')
                # Delete the role and log the response as a debug message
                response = check_for_iam_role(iam, sts_client).delete()
                usr_log(response, 'debug')
            except Exception as error:
                usr_log(f'Cleanup: Issue removing IAM role: {error}', 'error')

            usr_log("Complete. List of removed IAM roles/policies above (if empty there was nothing to delete)", "success")

        # Remove Security Groups
        do_remove_sg = user_choice("Do you want to remove any security groups created by this script")
        if do_remove_sg:
            try:
                # Wait for instances to terminate before trying to remove security group
                usr_log('Waiting for 5 seconds to ensure instances terminate...', 'info')
                sleep(5)
                usr_log('Deleting Security Groups...', 'info')
                # Get VPC Id
                all_vpcs = list(ec2.vpcs.filter(Filters=[{'Name': 'isDefault', 'Values': ['true']}]))
                default_vpc_id = all_vpcs[0].id

                # Get all security groups in the VPC that were created by this script (match description)
                sec_groups = list(ec2.security_groups.filter(Filters=[
                    {'Name': 'vpc-id', 'Values': [default_vpc_id]},
                    {'Name': 'description', 'Values': [sg_description]}
                ]))

                # Loop through the filtered list of groups and delete each one
                for group in sec_groups:
                    usr_log(f'Deleted group: {group.group_name} ({group.id})', 'info')
                    # Delete the group and log the response as a debug message
                    response = group.delete()
                    usr_log(response, 'debug')
            except Exception as error:
                usr_log(f'SG Delete Error: {error}', 'error')

            usr_log("Complete. List of removed security groups above (if empty there was nothing to delete)", "success")


# Run main function when script is called directly
if __name__ == '__main__':
    main()
