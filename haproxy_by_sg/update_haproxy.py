#/usr/bin/env python
"""configure haproxy by passing security group and specific item to capture in host 'name' tags

Todo:
- add real logger
- add more smarts around errors; haproxy init script seems to be dumb on debian
"""
import os
import sys
import time
import shutil
import boto.ec2
import subprocess
from subprocess import CalledProcessError
from argparse import ArgumentParser
from jinja2 import Environment, PackageLoader


def define_arguments():
    """ Define command line arguments.
    :return: Argparser object
    """
    std_args = ArgumentParser(add_help=True)
    std_args.add_argument("aws_region", help="a valid aws region: us-east-1, us-west-1, us-west-2, etc..")
    std_args.add_argument("sgroup_name", help="security group containing backend nodes")
    std_args.add_argument("unique_bit", help="unique portion used in instance naming to group instances")

    std_args.add_argument("--config-path", help="haproxy configuration path", default='/etc/haproxy/haproxy.cfg')
    std_args.add_argument("--connection-timeout", help="haproxy global connection_timeout", default='5000')
    std_args.add_argument("--client-timeout", help="haproxy global clitimeout", default='900000000')
    std_args.add_argument("--server-timeout", help="haproxy global srvtimeout", default='900000000')
    std_args.add_argument("--max-connections", help="haproxy global maxconn", default='200000')
    std_args.add_argument("--stats-auth-user", help="stats authentication user", default='stats')
    std_args.add_argument("--stats-auth-password", help="stats authentication password", default='stats123')
    std_args.add_argument("--app-name", help="application name for HAproxy", default='app1')
    std_args.add_argument("--app-mode", help="application name for HAproxy", default='tcp')
    std_args.add_argument("--app-algo", choices=['roundrobin','leastconn', 'static-rr','source'], default='roundrobin', help="application load balancing algorithm; choose roundrobin (default), leastconn, static-rr, source")
    std_args.add_argument("--app-maxconn", help="maximum number of connections per node; defaults to 10000", default=10000)
    std_args.add_argument("--app-maxqueue", help="NOT SUPPORTED: maximum number of connections to queue for a backend node; defaults to 0 (unlimited)", default=0)
    std_args.add_argument("--stats-port", help="stats port for HAproxy", default='8080')

    std_args.add_argument("--check-interval", help="haproxy server check interval", default='5000')
    std_args.add_argument("--check-rise", help="haproxy server check rise", default='2')
    std_args.add_argument("--check-fall", help="haproxy server check fall", default='3')
    ### BOOLS
    std_args.add_argument("--public-ip", help="use public ip", action="store_true", default=False)
    std_args.add_argument("--hard-restart", help="issue a hard restart instead of a soft restart", action="store_true", default=False)
    std_args.add_argument("--app-ssl", action="store_true", help="if the application uses SSL, this enables the ssl health check", default=True)
    std_args.add_argument("--dry-run", action="store_true", default=False)
    std_args.add_argument("--skip-restart", action="store_true", default=False)
    std_args.add_argument("--test", action="store_true", default=False)
    port_args = std_args.add_argument_group('port configuration')
    port_args.add_argument("--app-port", help="application port for HAproxy; sets listener port and backend port the same", default='80')
    spec_port_args = std_args.add_argument_group(title='alternate port mapping')
    spec_port_args.add_argument("--listener-port", help="incoming port HAproxy listens; replaces --app-port and requires --backend-port", default=None)
    spec_port_args.add_argument("--backend-port", help="backend port that workers listen; replaces --app-port and requires --listener-port", default=None)
    return std_args


def restore_old_config_and_die(conf_file, replacement_file):
    try:
        if os.path.isfile(replacement_file):
            shutil.move(replacement_file, conf_file)
            print "ERROR hit: restored previous version of {0}".format(conf_file)
            sys.exit(127)
    except Exception as e:
        print "ERROR: cannot restore {0} from {1}; {2}".format(conf_file, replacement_file, e)
        sys.exit(1)


def backup_old_config(conf_file, replacement_file):
    try:
        if os.path.isfile(conf_file):
            shutil.move(conf_file, replacement_file)
    except Exception as e:
        print "ERROR: cannot backup {0}; {1}".format(conf_file, e)
        sys.exit(1)


def soft_restart():
    '''
    calls init script to reload the configuration;
    persistent connections can lead to the previous process sitting around.
    '''
    restart_return = subprocess.check_call(['/etc/init.d/haproxy', 'reload'])
    if restart_return > 1:
        return False
    else:
        return True


def hard_restart():
    '''
    calls init script to do a hard restart of the daemon
    '''
    restart_return = subprocess.check_call(['/etc/init.d/haproxy', 'reload'])
    if restart_return > 1:
        return False
    else:
        return True


def main():
    should_i_write = False
    argparser = define_arguments()
    args = argparser.parse_args()
    if not args.aws_region:
        print "ERROR: specify region!"
        sys.exit(1)
    backend_addresses = {}
    template_variables = {}
    if args.test:
        backend_addresses['i-xaklsjh'] = '255.255.255.255'
    else:
        botoEC2 = boto.ec2.connect_to_region(args.aws_region)
        for r in botoEC2.get_all_instances(
            filters={'group-name': '*{0}*'.format(args.sgroup_name), 'tag:Name': '*{0}*'.format(args.unique_bit)}
        ):
            for inst in r.instances:
                if inst.state == 'running':
                    if args.public_ip:
                        backend_addresses[inst.id] = inst.ip_address
                    else:
                        backend_addresses[inst.id] = inst.private_ip_address
        if len(backend_addresses) < 1:
            print "ERROR: unable to find instances that match the sgroup_name and unique_bit provided"
            sys.exit(1)

    conf = Environment(loader=PackageLoader('haproxy_by_sg'), trim_blocks=True)
    template_name = 'haproxy.cfg'
    if args.app_port and (not args.listener_port and not args.backend_port):
        port_variables = {'app_port': args.app_port}
    elif args.listener_port and args.backend_port:
        port_variables = {
            'listener_port': args.listener_port,
            'backend_port': args.backend_port
        }
    else:
        print "ERROR: listener-port and backend-port must both be specified"
        sys.exit(1)
    template_variables = {
        'server_timeout': args.server_timeout,
        'client_timeout': args.client_timeout,
        'connection_timeout': args.connection_timeout,
        'max_connections': args.max_connections,
        'stats_port': args.stats_port,
        'stats_auth_user': args.stats_auth_user,
        'stats_auth_password': args.stats_auth_password,
        'app_name': args.app_name,
        'app_mode': args.app_mode,
        'backend_addresses': backend_addresses,
        'app_ssl': args.app_ssl,
        'app_balance_algo': args.app_algo,
        'app_maxconn': args.app_maxconn,
        'check_interval': args.check_interval,
        'check_rise': args.check_rise,
        'check_fall': args.check_fall
    }
    template_variables.update(port_variables)
    if not os.path.isfile(args.config_path):
        print "ERROR: config file %s doesn't exist" % args.config_path
        sys.exit(1)

    newfile = str(conf.get_template(template_name).render(template_variables)).split('\n')
    with open(args.config_path, 'r') as of:
        oldfile = of.read().splitlines()

    for oldl, newl in zip(oldfile, newfile):
        if oldl != newl:
            should_i_write = True
            if args.dry_run:
                print "replacing {0} ===> {1} ".format(oldl, newl)
    new_config_file_path = args.config_path + time.strftime("%Y%m%d-%H%M%S")
    if should_i_write:
        if args.dry_run:
            sys.exit(0)
        backup_old_config(args.config_path, new_config_file_path)
        try:
            with open(args.config_path, 'w') as f:
                f.write('\n'.join(newfile))
            if not args.skip_restart:
                if args.hard_restart:
                    restart_rslt = hard_restart()
                else:
                    restart_rslt = soft_restart()
                if not restart_rslt:
                    raise CalledProcessError('restart failed due to misconfiguration')
            else:
                print "Skipping restart of haproxy..."
        except CalledProcessError as e:
            print "ERROR restarting haproxy service: {0}".format(e)
            restore_old_config_and_die(args.config_path, new_config_file_path)
        except Exception as e:
            print "ERROR: {0}".format(e)


if __name__ == '__main__':
    main()
