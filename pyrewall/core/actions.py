from pyrewall.core.common import do_exec


def egress_failure():
    do_exec(['iptables', '-F', 'OUTPUT'])
    do_exec(['iptables', '-P', 'OUTPUT', 'ACCEPT'])
    do_exec(['iptables', '-I', 'INPUT', '-m', 'state', '--state', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    do_exec(['ip', 'route', 'add', 'default', 'via', ''])


def ingress_failure():
    pass

