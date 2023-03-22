import re
import subprocess
from typing import Union, Optional

import jc
from loguru import logger


class IPTables:
    def __init__(self):
        self.running = self.get_rules()

    @staticmethod
    def get_rules():
        running = {}
        try:
            cmd_output = subprocess.check_output(
                ["iptables", "-L", "-nv", "--line-numbers"], text=True
            )
            out = jc.parse("iptables", cmd_output)
        except Exception as exc:
            logger.error(f"Unable to get rules: {str(exc)}")
        else:
            for rule_set in out:
                chain = rule_set["chain"]
                rules = rule_set["rules"]
                running[chain] = rules
            return running

    def filter_rules(
        self,
        chain: str,
        element: str,
        regex: Union[str, list[str]],
        rules: Optional[list[dict]] = None,
    ):
        rules = rules or self.running
        regex = regex if isinstance(regex, list) else [regex]
        result = []
        rule: dict
        for rule in rules[chain]:
            for exp in regex:
                if re.match(exp, rule[element]):
                    result.append(rule)
        return result
