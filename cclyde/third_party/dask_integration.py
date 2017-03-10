import sys
import time


class DaskCluster(object):

    """
    To be inherited with Cluster to implement a Dask cluster
    """

    def launch_dask(self):
        """On a running cluster with anaconda installs and launches dask distributed in the current python_env
        :returns scheduler's address:port - used by dask.Client to submit jobs to."""

        # Ensure anaconda has been installed on cluster
        if not self.anaconda_installed:
            raise AssertionError('Need to have anaconda installed on cluster; run >>>cluster.install_anaconda()')

        # Locate mater, to use its internal ip address for worker nodes to connect to
        master = filter(lambda node: node.get('host_name', '').endswith('master'), self.nodes)
        if master:
            master = master[0]
        else:
            raise Warning('Master node not found in self.nodes')


        # Ensure distributed is installed on the cluster.
        sys.stdout.write('Installing dask.distributed on cluster\n')
        self.run_cluster_command('{}conda install distributed -y'.format(self.python_env_path),
                                 target='cluster')


        # Launch the scheduler on the master node
        # Need to launch it own detached screen.. also seems to need an initial output
        # so using python to print empty line to get return immediately.
        sys.stdout.write('\nLaunching scheduler on master node...')
        cmd = '{}dask-scheduler'.format(self.python_env_path, master.get('internal_ip'))
        cmd = 'screen -dmS dask_screen {} && {}python -c "print()"'.format(cmd, self.python_env_path)
        self.run_cluster_command(cmd,
                                 return_output=True,
                                 target='master',
                                 python_env_cmd=False)
        sys.stdout.write('Done.\n')
        time.sleep(4)  # Little bit of time for scheduler to get going, just in case


        # Launch the workers
        sys.stdout.write('\nLaunching workers...')
        # TODO: Add ability for --nprocs & --nthreads; now it defaults to one process with threads == n_cores
        cmd = '{}dask-worker {}:8786'.format(self.python_env_path, master.get('internal_ip'))
        cmd = 'screen -dmS dask_screen {} && {}python -c "print()"'.format(cmd, self.python_env_path)
        self.run_cluster_command(cmd,
                                 return_output=True,
                                 target='exclude-master',
                                 python_env_cmd=False)
        sys.stdout.write('Done.\n')

        scheduler_address = '{}'.format(master.get('public_ip'))
        sys.stdout.write('\nScheduler should be available here: {0}:8786'
                         '\nWeb Dashboard should be available here: {0}:8787'.format(scheduler_address))

        return scheduler_address + '8786'


