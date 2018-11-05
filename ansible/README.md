# Ansible deployment

The code can also be deployed using [Ansible](https://www.ansible.com/) with a playbook and a role.

## Code organization

TODO

## Roles

TODO

## Configuration

The ansible configuration is split in mainly two files: `ansible.cfg`, that sets a number of
defaults and the connection method used to reach the host, and `ssh.config` that contains
all the required configurations to allow ssh to connect to the remote host, linking this
to a different ssh configuration file allows for customization.

The `ansible.cfg` file sets some useful configuration:

- the `hostfile` directive specifies where to find the host file definition, if one is already available
- the `remote_user` directise sets the remote user to use when connecting to a remote host to provision it,
  this usually is required to be a user that can sudo without password.
- the `roles_path` directive allows setting a different path where ansible roles are stored, if any are avaialble

The `ssh.config` file limits the ssh connection key to be the one found in `HOME/.ssh/id_vulnman`, which
can be a link to a key or even a wrapper, allowing the user to customize _how_ ansible reaches the server
to deploy Vulnwhisperer on.

# Deploying

TODO
