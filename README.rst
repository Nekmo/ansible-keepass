Ansible Keepass Plugin
######################
Use **become** (sudo) in Ansible **without giving any password** and safely. This plugin connects to
**keepassHTTP** or **KeepassXC Browser** to request the password. The connection is encrypted and requires a first
confirmation. The token for Keepass HTTP is stored using the keyring of the system and the passwords are only
accessible while the Keepass database is open.

Installation
============
Clone or copy the plugin included::

    sudo mkdir -p /usr/local/share/ansible/plugins/vars
    sudo curl https://raw.githubusercontent.com/Nekmo/ansible-keepass/master/ansible_keepass.py \
         -o /usr/local/share/ansible/plugins/vars/ansible_keepass.py

Set the var plugins directory to the same directory that contains ``ansible_keepass.py`` in ``ansible.cfg``::

    /etc/ansible/ansible.cfg
    ------------------------

    [defaults]
    ...
    vars_plugins = /usr/local/share/ansible/plugins/vars


And install requirements from ``requirements.txt`` file in this project (install the modules in the same environment
as Ansible)::

    sudo pip install -r requirements.txt

Usage
=====
This project supports **KeepassHTTP** and **KeepassXC Browser**. This plugin is able to detect your Keepass
program automatically but if you have issues define the environment variable ``KEEPASS_CLASS`` (available values:
``KeepassXC`` and ``KeepassHTTP``).

*Ansible-keepass* uses the url of the entry to find the entry to use. In the Keepass entries you must specify the url
using the name of the inventory or inventory group. For example::

    ssh:<inventory name>

Or including username::

    ssh:<username>@<inventory name>

That is all! If you do not set a password now Ansible will ask Keepass for the password. You can try this plugin using::

    $  ansible <host_name> -a "/usr/bin/hdparm -C /dev/sda" --become


Security
========
These are the security measures adopted by Keepass and this plugin:

#. Keepass requests link permission the first time. This plugin stores the session using the OS Keyring.
#. Keepass can authorize access permission for each key individually.
#. Keys can not be listed using Keepass HTTP/XC Browser. A possible attacker must know key urls.
#. The connection between this plugin and Keepass is encrypted.
#. Passwords are not accessible while the Keepass database is closed.

This plugin can be more secure than copy&paste: a malware installed on your machine can listen for changes
in the clipboard. This plugin depends on the security of the OS Keyring and your personal password.
