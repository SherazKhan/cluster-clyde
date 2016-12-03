"""
MIT License

Copyright (c) 2016 Miles Granger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import requests

def get_ip():
    '''
    Helper function get to current external IP Address
    :return: external IP address in string format
    '''
    ip = requests.get('http://whatismyip.org')
    if ip.ok:
        return ip.content.split('<span')[1].split('>')[1].split('<')[0]
    return False


def get_dask_permissions(obj, ip):
    """
    Returns list of permissions required by dask
    :param obj: instance of cluster object which is initialized up to point of configuring security group
    :param ip: external ip address for allowed ip ranges
    :return: list of permissions formatted as required by boto3 for dask distributed
    """
    dask_permissions = [

        # Allow connection to port 22 for client and all nodes
        {'IpProtocol': 'tcp',
         'FromPort': 22,
         'ToPort': 22,
         'UserIdGroupPairs': [{'VpcId': obj.vpc.id,
                               'GroupId': obj.security_group.group_id, },
                              ],
         'IpRanges': [{'CidrIp': ip},
                      ],
         },

        # Allow connection to port 8786 for client and all nodes
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 8786,
         'IpRanges': [{'CidrIp': ip},
                      ],
         },

        # Allow connection to port 8787 for client and all nodes
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 8787,
         'IpRanges': [{'CidrIp': ip},
                      ],
         },

        # Allow connection to port 8787 for client and all nodes
        {'IpProtocol': 'tcp',
         'FromPort': 0,
         'ToPort': 65535,
         'UserIdGroupPairs': [{'VpcId': obj.vpc.id,
                               'GroupId': obj.security_group.group_id, },
                              ],
         },


    ]
    return dask_permissions
