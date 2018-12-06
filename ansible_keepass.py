import __main__
import json
import requests
from ansible.plugins.vars import BaseVarsPlugin
from ansible.executor.task_executor import TaskExecutor as _TaskExecutor
from ansible.executor import task_executor
from ansible.executor.process import worker
from keepasshttplib import keepasshttplib, httpclient, encrypter
from urllib3 import HTTPConnectionPool


class Keepass(object):
    def __init__(self):
        self.k = keepasshttplib.Keepasshttplib()

    def get_password(self, host):
        if not self.test_connection():
            print('Keepass is closed! sudo password is not available.')
            return
        hosts = [host.name] + [group.name for group in host.groups]
        for host_name in hosts:
            auth = self.k.get_credentials('ssh://{}'.format(host_name))
            if auth:
                return auth[1]
        print('The password could not be obtained for {}'.format(', '.join(map(str, hosts))))
        return

    def test_connection(self):
        key = self.k.get_key_from_keyring()
        if key is None:
            key = encrypter.generate_key()
        id_ = self.k.get_id_from_keyring()
        try:
            return self.k.test_associate(key, id_)
        except requests.exceptions.ConnectionError:
            return

    @classmethod
    def get_or_create_conn(cls):
        if not getattr(__main__, '_keepass', None):
            __main__._keepass = Keepass()
        return __main__._keepass


class TaskExecutor(_TaskExecutor):
    def __init__(self, host, task, job_vars, play_context, new_stdin, loader, shared_loader_obj, final_q):
        if play_context.become and not job_vars.get('ansible_become_pass'):
            kp = Keepass.get_or_create_conn()
            password = kp.get_password(host)
            if password:
                job_vars['ansible_become_pass'] = password
        super(TaskExecutor, self).__init__(host, task, job_vars, play_context, new_stdin, loader,
                                           shared_loader_obj, final_q)


setattr(task_executor, 'TaskExecutor', TaskExecutor)
setattr(worker, 'TaskExecutor', TaskExecutor)


class VarsModule(BaseVarsPlugin):

    """
    Loads variables for groups and/or hosts
    """

    def get_vars(self, loader, path, entities):
        super(VarsModule, self).get_vars(loader, path, entities)
        return {}

    def get_host_vars(self, *args, **kwargs):
        return {}

    def get_group_vars(self, *args, **kwargs):
        return {}

