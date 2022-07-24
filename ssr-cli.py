#!/usr/bin/python3
# -*- coding: utf-8 -*-

def ss_command(ssr_dict):
    """
    example ssr_dict:
    {"remarks": "", "group": "FISH", "server": "127.0.0.1", "server_port": 8081, "method": "none", "obfs": "plain", "password": "37gct36asx", "protocol": "auth_chain_a", "udp_timeout": 66, "udp_cache": 64, "fast_open": false, "verbose": false, "connect_verbose_info": 0, "protocol_param": "", "obfs_param": "", "id": 0, "ping": "", "connect": false, "daemon": "start", "local_address": "0.0.0.0", "local_port": 1080, "timeout": 66, "workers": 2, "pid-file": "/home/fish/.ssr-command-client/shadowsocksr.pid", "log-file": "/home/fish/.ssr-command-client/shadowsocksr.log"}
    """

    import shadowsocksr_cli.handle_utils

    import signal
    from shadowsocksr_cli.shadowsocks import daemon, eventloop, tcprelay, udprelay, asyncdns
    from shadowsocksr_cli.logger import logger

    logger.info("command is: {0}".format(ssr_dict));

    if not ssr_dict.get('dns_ipv6', False):
        asyncdns.IPV6_CONNECTION_SUPPORT = False
    try:
        daemon.daemon_exec(ssr_dict)
        dns_resolver = asyncdns.DNSResolver()
        tcp_server = tcprelay.TCPRelay(ssr_dict, dns_resolver, True)
        udp_server = udprelay.UDPRelay(ssr_dict, dns_resolver, True)
        loop = eventloop.EventLoop()
        dns_resolver.add_to_loop(loop)
        tcp_server.add_to_loop(loop)
        udp_server.add_to_loop(loop)

        def handler(signum, _):
            logger.info('received SIGQUIT, doing graceful shutting down..')
            tcp_server.close(next_tick=True)
            udp_server.close(next_tick=True)

        signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

        def int_handler(signum, _):
            logger.info("Shadowsocksr is stop")
            sys.exit(1)

        signal.signal(signal.SIGINT, int_handler)
        daemon.set_user(ssr_dict.get('user', None))
        logger.info('Shadowsocksr is start on {0}:{1}'.format(ssr_dict['local_address'], ssr_dict['local_port']))
        loop.run()
    except Exception as e:
        logger.error(e)
        sys.exit(1)

def ss_execute(config_path, mode):
    """
    config_path: path of config file
    mode: "start" or "stop"
    """
    import json
    from shadowsocksr_cli.logger import logger

    logger.info("config_path={0}, mode={1}".format(config_path, mode))

    with open(config_path, "r") as fd:
        config_txt = fd.read()

    ssr_dict = json.loads(config_txt)
    ssr_dict["daemon"] = mode

    ss_command(ssr_dict)

if __name__ == "__main__":
    import sys
    config_path = sys.argv[1]
    mode = sys.argv[2]

    ss_execute(config_path, mode)
