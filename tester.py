import aiohttp
import asyncio
import ssl
from aiohttp_socks import ProxyConnector
from pathlib import Path
import re

proxy_sources = [
    # SOCKS4
    {"type": 4, "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4"},
    {"type": 4, "url": "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4"},
    {"type": 4, "url": "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all"},
    {"type": 4, "url": "https://api.openproxylist.xyz/socks4.txt"},
    {"type": 4, "url": "https://proxyspace.pro/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS4_RAW.txt"},
    {"type": 4, "url": "http://worm.rip/socks4.txt"},
    {"type": 4, "url": "https://www.proxy-list.download/api/v1/get?type=socks4"},
    {"type": 4, "url": "https://www.proxyscan.io/download?type=socks4"},
    {"type": 4, "url": "https://www.my-proxy.com/free-socks-4-proxy.html"},
    {"type": 4, "url": "http://www.socks24.org/feeds/posts/default"},
    {"type": 4, "url": "https://www.freeproxychecker.com/result/socks4_proxies.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks4.txt"},
    {"type": 4, "url": "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS4.txt"},

    # SOCKS5
    {"type": 5, "url": "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks5.txt"},
    {"type": 5, "url": "https://api.openproxylist.xyz/socks5.txt"},
    {"type": 5, "url": "https://api.proxyscrape.com/?request=displayproxies&proxytype=socks5"},
    {"type": 5, "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5"},
    {"type": 5, "url": "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all&simplified=true"},
    {"type": 5, "url": "https://proxyspace.pro/socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/manuGMG/proxy-365/main/SOCKS5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt"},
    {"type": 5, "url": "https://raw.githubusercontent.com/BlackSnowDot/proxylist-update-every-minute/main/socks.txt"},
    {"type": 5, "url": "http://worm.rip/socks5.txt"},
    {"type": 5, "url": "https://www.proxy-list.download/api/v1/get?type=socks5"},

    # HTTP
    {"type": 1, "url": "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt"},
    {"type": 1, "url": "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt"},
    {"type": 1, "url": "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt"},
    {"type": 1, "url": "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt"},
    {"type": 1, "url": "https://api.proxyscrape.com/?request=displayproxies&proxytype=http"},
    {"type": 1, "url": "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt"},
    {"type": 1, "url": "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt"},
    {"type": 1, "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt"},
    {"type": 1, "url": "https://raw.githubusercontent.com/BlackSnowDot/proxylist-update-every-minute/main/http.txt"},
]

output_files = {
    1: Path("working_http.txt"),
    4: Path("working_socks4.txt"),
    5: Path("working_socks5.txt")
}

headers = {"User-Agent": "Mozilla/5.0"}
timeout = aiohttp.ClientTimeout(total=10)
test_url = "http://example.com"
seen = set()
sem = asyncio.Semaphore(1000)

async def fetch_proxy_list(session, source):
    try:
        async with session.get(source["url"], timeout=timeout) as res:
            text = await res.text()
            proxies = re.findall(r"\d+\.\d+\.\d+\.\d+:\d+", text)
            return source["type"], proxies
    except:
        return source["type"], []

async def write_proxy(ptype, proxy):
    try:
        with open(output_files[ptype], "a", encoding="utf-8", buffering=1) as f:
            f.write(proxy + "\n")
            f.flush()
    except Exception as e:
        print(f"Failed to write proxy: {proxy} -> {e}")

async def test_proxy(proxy, ptype):
    async with sem:
        scheme = {1: "http", 4: "socks4", 5: "socks5"}[ptype]
        try:
            if ptype in [4, 5]:
                connector = ProxyConnector.from_url(f"{scheme}://{proxy}")
                async with aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers) as session:
                    async with session.get(test_url, ssl=False) as r:
                        if r.status == 200:
                            print(f"[✓] {scheme.upper()} {proxy}")
                            await write_proxy(ptype, proxy)
            else:
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                    async with session.get(test_url, proxy=f"http://{proxy}", ssl=False) as r:
                        if r.status == 200:
                            print(f"[✓] {scheme.upper()} {proxy}")
                            await write_proxy(ptype, proxy)
        except:
            pass

async def main():
    # Clear previous files
    for f in output_files.values():
        f.unlink(missing_ok=True)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        tasks = [fetch_proxy_list(session, src) for src in proxy_sources]
        results = await asyncio.gather(*tasks)

    proxy_tests = []
    for ptype, proxies in results:
        for proxy in proxies:
            if proxy not in seen:
                seen.add(proxy)
                proxy_tests.append(test_proxy(proxy, ptype))

    await asyncio.gather(*proxy_tests)

if __name__ == "__main__":
    asyncio.run(main())
