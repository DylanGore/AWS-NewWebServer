#!/bin/env python3

# This file is intended to be run directly on an AWS EC2 instance with
# permissions to write CloudWatch metric data

import subprocess
import boto3
import requests
from os import path, remove
from datetime import datetime, timezone

timestamp = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
cw_client = boto3.client("cloudwatch", "eu-west-1")


def main():
    """
    Main function
    """
    download_apache_stats()
    print(f'{timestamp}\tRun script')


def download_apache_stats():
    """
    Download the Apache satistics page from the instance using curl,
    extract the number of access requests and push it to CloudWatch
    """
    try:
        r = requests.post('http://169.254.169.254/latest/meta-data/instance-id')
        inst_id = r.text
        print(r.text)
    except Exception as error:
        print(error)

    if path.exists('apache_stats.txt'):
        remove("apache_stats.txt")

    # Download server status page
    try:
        print("Downloading Apache stats")
        subprocess.run(['curl', '-o', 'apache_stats.txt', f'http://127.0.0.1/server-status?auto'], check=True)
    except Exception as error:
        print(f"Error downloading Apache stats: {error}")

    print("Reading Apache stats file")
    file = open("apache_stats.txt", "r")
    # Read the file line by line and store the results in the relevent variables
    # https://stackoverflow.com/questions/12330522/reading-file-without-newlines-in-python
    try:
        raw_stats = file.read().splitlines()
        httpd_access = raw_stats[13]
        print(f"Number of Access Requests: {httpd_access[16:]}")

        # Push metric to CloudWatch
        response = cw_client.put_metric_data(
            Namespace='WIT_DEVOPS/APACHE',
            MetricData=[
                {
                    'MetricName': 'AccessReq',
                    'Timestamp': datetime.now(timezone.utc),
                    'Dimensions': [{'Name': 'Instance', 'Value': inst_id}],
                    'Value': int(httpd_access[16:]),
                    'Unit': 'None'
                },
            ]
        )

        # print(response)

    except Exception as error:
        print(f"File read error: {error}")


if __name__ == '__main__':
    main()
