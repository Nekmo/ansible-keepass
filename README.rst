Ansible Keepass Plugin
######################
Use **become** (sudo) in Ansible **without giving any password** and safely. This plugin connects to
**keepass HTTP** to request the password. The connection is encrypted and requires a first confirmation.
The token for Keepass HTTP is stored using the keyring of the system and the passwords are only accessible
while the Keepass database is open.

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


And install this requirement (install the module in the same environment as Ansible)::

    sudo pip install keepasshttplib

Usage
=====
You need a version of Keepass with support for Keepass HTTP. If you use **Keepass**, install the HTTP plugin. If you
need support for ``.kdbx`` (Keepass 2) databases you can install **KeepassXC**. This plugin does not currently support
*KeepassXC Browser* so you must enable support for Keepass HTTP.

This plugin uses the url of the entry to find the entry to use. In the Keepass entries you must specify the url
using the name of the inventory or inventory group. For example::

    ssh:<inventory name>

Or including username::

    ssh:<username>@<inventory name>

That is all! If you do not set a password now Ansible will ask Keepass for the password.

Security
========
These are the security measures adopted by Keepass HTTP and this plugin:

#. Keepass HTTP requests link permission the first time. This plugin stores the session using the OS Keyring.
#. Keepass HTTP can authorize access permission for each key individually.
#. The keys can not be listed using Keepass HTTP. A possible attacker must know key urls.
#. The connection between this plugin and Keepass is encrypted.
#. Passwords are not accessible while the Keepass database is closed.

This plugin can be more secure than copy&paste: a malware installed on your machine can listen for changes
in the clipboard. This plugin depends on the security of the OS Keyring and your personal password.

