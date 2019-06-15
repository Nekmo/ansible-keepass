from pathlib import Path

import __main__
import requests
import keyring
from ansible.plugins.vars import BaseVarsPlugin
from ansible.executor.task_executor import TaskExecutor as _TaskExecutor
from ansible.executor import task_executor
from ansible.executor.process import worker
from keepasshttplib import keepasshttplib, encrypter
from keepassxc_browser import Identity, Connection
from keepassxc_browser.protocol import ProtocolError


KEEPASSXC_CLIENT_ID = 'python-keepassxc-browser'
KEYRING_KEY = 'assoc'


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
            # __main__._keepass = Keepass()
            __main__._keepass = KeepassXC()
        return __main__._keepass


class KeepassXC(object):
    def __init__(self):
        self.identity = self.get_identity()
        self.connection = self.get_connection(self.identity)

    def get_identity(self):
        data = keyring.get_password(KEEPASSXC_CLIENT_ID, KEYRING_KEY)
        if data:
            identity = Identity.unserialize(KEEPASSXC_CLIENT_ID, data)
        else:
            identity = Identity(KEEPASSXC_CLIENT_ID)
        return identity

    def get_connection(self, identity):
        c = Connection()
        c.connect()
        c.change_public_keys(identity)
        try:
            c.get_database_hash(identity)
        except ProtocolError as ex:
            print(ex)
            exit(1)

        if not c.test_associate(identity):
            c.associate(identity)
            assert c.test_associate(identity), "Keepass Association failed"
            data = identity.serialize()
            keyring.set_password(KEEPASSXC_CLIENT_ID, KEYRING_KEY, data)
            del data

        return c

    def get_password(self, host):
        return next(iter(self.connection.get_logins(self.identity, url='ssh:{}'.format(host))), {}).get('password')


class TaskExecutor(_TaskExecutor):
    def __init__(self, host, task, job_vars, play_context, new_stdin, loader, shared_loader_obj, final_q):
        become = task.become or play_context.become
        if become and not job_vars.get('ansible_become_pass'):
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

