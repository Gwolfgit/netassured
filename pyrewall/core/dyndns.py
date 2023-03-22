import re

import ipaddress
from tenacity import wait_fixed, retry, TryAgain
from loguru import logger

from pyrewall.config import DynDnsConfig
from pyrewall.core.common import jc_exec, do_exec, round_robin
from pyrewall.core.firewall import IPTables

# Do not modify
Config = DynDnsConfig()
pmt = Config.prompt


class DynDns:
    def __init__(self):
        self._ipt = IPTables()
        self._hosts = Config.hosts
        self.ip = None
        self.chains = {"INPUT": "source", "OUTPUT": "destination"}
        self.ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s\*\/"
        self.dyn_regex = {
            "INPUT": r"\/\*\sDynDns\:INPUT\:{}",
            "OUTPUT": r"\/\*\sDynDns\:OUTPUT\:{}",
        }

    @property
    def is_valid_ip(self):
        v = ipaddress.ip_address(self.ip)
        return all([
            not v.is_multicast,
            not v.is_reserved,
            not v.is_link_local,
            not v.is_private,
            not v.is_loopback,
            not v.is_unspecified,
        ])

    @retry(wait=wait_fixed(Config.retry_delay))
    def get_latest(self):
        host = round_robin(self._hosts)

        logger.info(f"{pmt} Lookup: {host}")

        data = jc_exec("dig", ["dig", "+noall", "+answer", host, "A"])
        try:
            self.ip = data[0]["answer"][0]["data"]
        except (KeyError, IndexError):
            raise TryAgain
        else:
            if not self.is_valid_ip:
                logger.info(f"{pmt} Resolved {host} to invalid address: {self.ip}")
                logger.info(f"{pmt} Retrying with next host.")
                raise TryAgain

            if not self.rule_exists():
                logger.info(f"{pmt} No ruleset for {self.ip}")
                self.update_rules()
            else:
                logger.info(f"{pmt} Ruleset exists for {self.ip}")
                return True

    def rule_exists(self):
        r = []

        for chain, element in self.chains.items():
            rules = self._ipt.filter_rules(
                chain, "options", self.dyn_regex[chain].format(re.escape(self.ip))
            )
            r.append(bool(len(rules)))
            for rule in rules:
                r.append(True if re.match(re.escape(self.ip), rule[element]) else False)
                break
        return all(r)

    def update_rules(self):
        logger.info(f"{pmt} Adding new ruleset for {self.ip}")

        flags = {"source": "-s", "destination": "-d"}
        for chain, element in self.chains.items():
            logger.info(f"Adding {chain} rule for {element}: {self.ip}")

            run_cmd = ["iptables", "-I", str(chain)]
            run_cmd.extend([str(flags[element]), str(self.ip)])
            run_cmd.extend(["-j", "ACCEPT"])
            run_cmd.extend(["-m", "comment", "--comment", f"DynDns:{str(chain)}:{str(self.ip)}"])

            do_exec(run_cmd)
        return True

    def remove_old(self):
        def recurse(rc):
            return self._ipt.filter_rules(
                rc, "options", self.dyn_regex[rc].format(self.ip_regex)
            )

        for chain, element in self.chains.items():
            rule_chain = recurse(chain)
            logger.info(f"{pmt} {len(rule_chain)} {chain} rules exist.")
            for _ in range(len(rule_chain)):

                logger.debug(
                    f'Checking {chain} {element}: {rule_chain[0][element]} id: {str(rule_chain[0]["num"])}'
                )
                if re.match(re.escape(self.ip), rule_chain[0][element]):
                    if len(rule_chain) == 1:
                        logger.debug(
                            f'Ignoring single rule matching: {self.ip}'
                        )
                        break
                else:
                    try:
                        logger.info(f'Deleting {chain} {element}: {rule_chain[0][element]} id: {str(rule_chain[0]["num"])}')
                        do_exec(["iptables", "-D", chain, str(rule_chain[0]["num"])])
                    except IndexError:
                        continue
                    else:
                        rule_chain = recurse(chain)

