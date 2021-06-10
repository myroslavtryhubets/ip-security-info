import logging, sys, random, requests
from abc import ABC, abstractmethod
from datetime import datetime
from pprint import pprint
from functools import lru_cache

def get_key():
    with open('keys.txt') as read_file:
        file_lines = read_file.read().splitlines()
        return random.choice(file_lines)

logging.basicConfig(level=logging.INFO)

class IFetchUrl(ABC):

    @abstractmethod
    def get_data(self, url: str) -> dict:
        pass

    @abstractmethod
    def get_headers(self, data: dict) -> dict:
        pass


class FetchUrl(IFetchUrl):

    def get_data(self, ip: str) -> dict:
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {
            'apikey': get_key(), 'ip': ip}
        response = requests.get(url, params=params)
        data = response.json()
        return data

    def get_headers(self, data: dict) -> dict:
        return data["headers"]


class ExcFetchUrl(IFetchUrl):

    def __init__(self) -> None:
        self._fetch_url = FetchUrl()

    def get_data(self, ip: str) -> dict:
        try:
            data = self._fetch_url.get_data(ip)
            logging.info(f"Getting the data at {datetime.now()}")
            return data

        except requests.ConnectTimeout:
            logging.error("Connection time out. Try again later.")

        except requests.ReadTimeout:
            logging.error("Read timed out. Try again later.")

        except ValueError:
            logging.error("Request limit exceeded.  Try again later.")

    def get_headers(self, data: dict) -> dict:
        headers = self._fetch_url.get_headers(data)
        logging.info(f"Getting the headers at {datetime.now()}")
        return headers

class CacheFetchUrl(IFetchUrl):
    def __init__(self) -> None:
        self._fetch_url = ExcFetchUrl()

    @lru_cache(maxsize=64)
    def get_data(self, url: str) -> dict:
        data = self._fetch_url.get_data(url)
        return data

    def get_headers(self, data: dict) -> dict:
        headers = self._fetch_url.get_headers(data)
        return headers


if __name__ == "__main__":

    fetch = CacheFetchUrl()
    while(True):
        ipaddress = input("ip address - ")
        data = fetch.get_data(ipaddress)
        pprint(data)
        print(f"Cache Info: {fetch.get_data.cache_info()}")