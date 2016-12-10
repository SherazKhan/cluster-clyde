# Documentation for Cluster class 


**Methods**

---

`
def __init__(self,
              key_name='cclyde_default',
              cluster_name='default',
              n_nodes=2,
              ami='ami-40d28157',
              instance_type='t2.micro',
              python_env='default')
`<br/>

Constructor for cluster management object
:param key_name: str - string of existing key name, if it doesn't exist it will be created.
                      this only refers to the name as: '<pem_key>.pem'<br/>
:param cluster_name: str - name of this new cluster, this is given as a tag to created instances to allow
       reconnection/starting of instances.<br/>
:param n_nodes: int - Number of nodes to launch<br/>
:param ami: str - Amazon Machine Image code<br/>
:param instance_type: str - The type of EC2 instances to launch.<br/>
:param python_env: str - name of python environment to use,
                         default --> /home/ubuntu/anaconda/bin,
                         other --> /home/ubuntu/anaconda/envs/<python_env>/bin<br/>
                         
---

`
def make_credentials_file(aws_access_key_id, aws_secret_access_key)
`<br/>
*static method*
Creates a credential file for user
be careful, this overwrites any existing credential file<br/>
:param aws_access_key_id: str - Access key id given by AWS<br/>
:param aws_secret_access_key: str - secret key provided in association with key id from AWS<br/>

---

`
def make_config_file(region)
`<br/>
Creates a config file for user
be careful, this overwrites any existing config file
@param region: str - AWS region ie. us-east-1

---

`
def configure()
`<br/>
Runs all configuration methods, before start_cluster() method.


---

`
def install_anaconda()
`<br/>

Installs the Anaconda Distribution of Python on all nodes

---

`
def install_python_packages(packages, method='pip', target='cluster', only_exit_codes=True)
`<br/>

Convenience function to install python package(s)
packages: list - list of packages to install into current python_env environment. ie ['numpy', 'pandas==18.0']
For more control over installation of packages to specific nodes use
run_cluster_command('pip install <package>', target=<node name>, python_env_cmd=True)

---

`
def launch_dask()
`<br/>

Handles the launching of dask distributed on the cluster. This ensures Dask.Distributed is installed, and then launches
the scheduler on the master node and connects all Dask workers to the scheduler endpoint. Returns the scheduler endpoint; 
<scheduler_public_ip>:8786

---

`
def run_cluster_command(command, target='cluster', python_env_cmd=False, return_output=False)
`
Run a command on the cluster, master, or specific target (node name, public or internal ip)<br/>
:param command: str - command to be executed. ie. 'date'<br/>
:param target: str - target node(s) to execute command on. cluster, master, exclude-master or the node name,
                     internal ip, or public ip address<br/>
:param python_env_cmd: bool - If true, the absolute path to current python_env is used pre-pended to command.
                              ie. "python myscript.py" --> "/home/ubuntu/<python_env_path>/python myscript.py"<br/>
:param return_output: bool - Whether to print the stdout which results from the command.<br/>
:return: None<br/>


---

`
def launch_instances_nonblocking()
`<br/>

Launch instances without blocking the main thread.

---

`
def launch_instances()
`<br/>

Launch instances while blocking the main thread.

---

`
def reconnect_to_cluster()
`<br/>
Given a configured cluster object, reconnect to a cluster with the configured
`cluster_name`

---

`
def stop_cluster()
`<br/>

Stop a cluster, can later reconnect to it with `cluster.reconnect_to_cluster()` <br/>
**NOTE**: The `cluster_name` attribute must be the same in order to reconnect to a stopped cluster.

---

`
def terminate_cluster()
`<br/>

Kill all instances on the current cluster

---

**Notable Attributes**

---

`.nodes`<br/>

A list of dictionaries specifying node names, public and internal ip addresses.<br/><br/>

`cluster_name`<br/>
The name of the current cluster. All instances are given this as a key/value so that when running `.stop_cluster()`
of if connection is otherwise lost, one can later reconnect to it.<br/><br/>

`python_env`<br/>
The current Python environment. Creating new python environments has not been implemented as of v0.0.1.
Defaults to `~/anaconda/bin`<br/><br/>
