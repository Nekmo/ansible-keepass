import os

import psutil

import __main__
import requests
import keyring
from ansible.plugins.vars import BaseVarsPlugin
from ansible.executor.task_executor import TaskExecutor as _TaskExecutor
from ansible.executor import task_executor
from ansible.executor.process import worker
from ansible.utils.display import Display
from keepasshttplib import keepasshttplib, encrypter
from keepassxc_browser import Identity, Connection
from keepassxc_browser.protocol import ProtocolError


KEEPASSXC_CLIENT_ID = 'python-keepassxc-browser'
KEEPASSXC_PROCESS_NAMES = set(('keepassxc', 'keepassxc.exe',
                               'keepassxc-proxy'))
KEYRING_KEY = 'assoc'


display = Display()


class NONE:
    pass


class AnsibleKeepassError(Exception):
    body = 'Error in the Ansible Keepass plugin.'

    def __init__(self, msg=''):
        body = self.body
        if msg:
            body += ' {}'.format(msg)
        super().__init__(body)


class KeepassConnectionError(AnsibleKeepassError):
    body = 'Error on connection.'


class KeepassHTTPError(AnsibleKeepassError):
    body = 'The password for root could not be obtained using Keepass HTTP.'


class KeepassXCError(AnsibleKeepassError):
    body = 'The password for root could not be obtained using KeepassXC Browser.'


class KeepassBase(object):
    def __init__(self):
        self.cached_passwords = {}

    def get_cached_password(self, host):
        hosts = get_host_names(host)
        for host_name in hosts:
            return self._get_cached_password(host_name)

    def _get_cached_password(self, host_name):
        password = self.cached_passwords.get(host_name, NONE)
        if password is NONE:
            password = self.get_password(host_name)
            self.cached_passwords[host_name] = password
        return password

    def get_password(self, host):
        raise NotImplementedError


class KeepassHTTP(KeepassBase):
    def __init__(self):
        super(KeepassHTTP, self).__init__()
        self.k = keepasshttplib.Keepasshttplib()

    def get_password(self, host_name):
        if not self.test_connection():
            raise KeepassHTTPError('Keepass is closed!')
        try:
            auth = self.k.get_credentials('ssh://{}'.format(host_name))
        except Exception as e:
            raise KeepassHTTPError('Error obtaining host name {}: {}'.format(host_name, e))
        if auth:
            return auth[1]

    def test_connection(self):
        key = self.k.get_key_from_keyring()
        if key is None:
            key = encrypter.generate_key()
        id_ = self.k.get_id_from_keyring()
        try:
            return self.k.test_associate(key, id_)
        except requests.exceptions.ConnectionError as e:
            raise KeepassHTTPError('Connection Error: {}'.format(e))


class KeepassXC(KeepassBase):
    _connection = None

    def __init__(self):
        super(KeepassXC, self).__init__()
        try:
            self.identity = self.get_identity()
        except Exception as e:
            raise KeepassConnectionError('The identity could not be obtained from KeepassXC: {}'.format(e))

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
        c.get_database_hash(identity)

        if not c.test_associate(identity):
            c.associate(identity)
            assert c.test_associate(identity), "Keepass Association failed"
            data = identity.serialize()
            keyring.set_password(KEEPASSXC_CLIENT_ID, KEYRING_KEY, data)
            del data
        return c

    @property
    def connection(self):
        if self._connection is None:
            try:
                self._connection = self.get_connection(self.identity)
            except ProtocolError as e:
                raise AnsibleKeepassError('ProtocolError on connection: {}'.format(e))
            except Exception as e:
                raise AnsibleKeepassError('Error on connection: {}'.format(e))
        return self._connection

    def get_password(self, host_name):
        try:
            logins = self.connection.get_logins(self.identity, url='ssh:{}'.format(host_name))
        except ProtocolError:
            return
        except Exception as e:
            raise KeepassXCError('Error obtaining host name {}: {}'.format(host_name, e))
        return next(iter(logins), {}).get('password')


def get_host_names(host):
    return [host.name] + [group.name for group in host.groups]


def get_keepass_class():
    keepass_class = os.environ.get('KEEPASS_CLASS')
    if not keepass_class and \
            next(filter(lambda p: (p.name() or '').lower() in KEEPASSXC_PROCESS_NAMES, psutil.process_iter()), None):
        keepass_class = 'KeepassXC'
    return {
        'KeepassXC': KeepassXC,
        'KeepassHTTP': KeepassHTTP,
    }.get(keepass_class, KeepassHTTP)


def get_or_create_conn(cls):
    if not getattr(__main__, '_keepass', None):
        __main__._keepass = cls()
    return __main__._keepass


class TaskExecutor(_TaskExecutor):
    def __init__(self, host, task, job_vars, play_context, new_stdin, loader, shared_loader_obj, final_q):
        become = task.become or play_context.become
        if become and not job_vars.get('ansible_become_pass'):
            password = NONE
            cls = get_keepass_class()
            try:
                kp = get_or_create_conn(cls)
                password = kp.get_cached_password(host)
            except AnsibleKeepassError as e:
                display.error(e)
            if password is None:
                display.warning('The password could not be obtained using {}. Hosts tried: {}. Maybe the password is '
                                'not in the database or does not have the url.'.format(
                    cls.__name__, ', '.join(get_host_names(host))))
            elif password not in [None, NONE]:
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
