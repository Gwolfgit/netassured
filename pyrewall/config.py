# Configuration settings
from collections import deque

from pydantic import BaseModel


# NetAssure
class NetAssureConfig(BaseModel):
    prompt: str = "NetAssure>"
    my_ip: str = ""
    my_port: int = 1111
    fix_egress: bool = False
    fix_ingress: bool = False
    in_urls: deque = []
    out_urls: deque = ["https://www.google.com", "https://www.facebook.com"]
    retry_delay: int = 10
    timeout: int = 5
    attempts: int = 3


# DynDns
class DynDnsConfig(BaseModel):
    hosts: deque = deque([])
    retry_delay: int = 10
    prompt: str = "DynDns>"


