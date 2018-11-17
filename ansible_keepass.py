from ansible.plugins.vars import BaseVarsPlugin
from ansible.executor.task_executor import TaskExecutor as _TaskExecutor
from ansible.executor import task_executor
from ansible.executor.process import worker
from keepasshttplib import keepasshttplib

k = keepasshttplib.Keepasshttplib()


def get_password(host):
    for host_name in [host.name] + [group.name for group in host.groups]:
        auth = k.get_credentials('ssh://{}'.format(host_name))
        if auth:
            return auth[1]


class TaskExecutor(_TaskExecutor):
    def __init__(self, host, task, job_vars, play_context, new_stdin, loader, shared_loader_obj, final_q):
        if play_context.become and not job_vars.get('ansible_become_pass'):
            job_vars['ansible_become_pass'] = get_password(host)
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

