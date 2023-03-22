import socket
import asyncio

import requests
from tenacity import wait_fixed, retry, TryAgain, stop_after_attempt
from loguru import logger

from pyrewall.config import NetAssureConfig as Config
from pyrewall.core.actions import ingress_failure, egress_failure
from pyrewall.core.common import round_robin

pmt = Config.prompt


class NetAssure:

    def __init__(self):
        pass

    def run_checks(self):
        pass

    # Ingress Tests
    def check_ingress(self):
        logger.info(f'{pmt} Executing ingress test.')
        try:
            out = asyncio.run(self.test_ingress())
        except Exception as exc:
            logger.warning(f'{pmt} Ingress test failed.')
            logger.warning(exc)
            return False
        else:
            logger.info(f'{pmt} Ingress test passed.')
            return True

    async def test_ingress(self):
        logger.info(f"{pmt} Executing ingress test.")
        a, b = await asyncio.gather(self.ingress_request(), self.server())
        return all([a, b])

    @staticmethod
    async def server():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((Config.my_ip, Config.my_port))
                s.listen()
                conn, addr = s.accept()
                logger.info(f"{pmt} Started server on {Config.my_ip}:{Config.my_port}")
                with conn:
                    logger.info(f"{pmt} Connection from {addr}")
                    while True:
                        data = b"HTTP/1.1 200 OK\n"
                        conn.sendall(data)
                        return True
        except Exception as exc:
            logger.warning(f"{pmt} {str(exc)}")
            return False

    @retry(wait=wait_fixed(Config.retry_delay), stop=stop_after_attempt(Config.attempts))
    async def ingress_request(self):
        for url in round_robin(Config.in_urls):
            logger.debug(f'{pmt} Attempting connection to: {url}')
            try:
                requests.get(url, timeout=Config.timeout)
            except requests.exceptions.RequestException as exc:
                logger.info(f"{pmt} Failed request to {url}: {str(exc)}")
                raise TryAgain
            except Exception as exc:
                logger.warning(f"{pmt} Server error: {str(exc)}")
                return False
            else:
                return True

    # Egress Tests
    def check_egress(self):
        logger.info(f"{pmt} Executing egress test.")
        try:
            self.test_egress()
        except Exception as exc:
            logger.warning(f'{pmt} Egress test failed.')
            logger.warning(exc)
            return False
        else:
            logger.info(f'{pmt} Egress test passed.')
            return True

    @retry(wait=wait_fixed(Config.retry_delay), stop=stop_after_attempt(Config.attempts))
    def test_egress(self):
        try:
            for url in round_robin(Config.out_urls):
                logger.info(f"{pmt} Trying {url}")
                try:
                    requests.get(url, timeout=Config.timeout)
                except requests.exceptions.RequestException as exc:
                    logger.debug(f"{pmt} Failed request to {url}: {exc}")
                    raise TryAgain
        except TryAgain:
            raise TryAgain
        except Exception as exc:
            logger.warning(f"{pmt} All egress attempts failed: {exc}")
            return False
        else:
            logger.info(f"{pmt} Egress test passed.")
            return True







cc = CheckConnect()
cc.check_egress()
cc.check_ingress()
