import asyncio
import aiohttp
import aiofiles

# List of proxy sources (30 URLs)
proxy_sources = [
    # GitHub-hosted raw lists (23)
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/proxylist-to/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies_anonymous/http.txt",
    "https://raw.githubusercontent.com/zeynoxwashere/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
    "https://raw.githubusercontent.com/ryanhaticus/superiorproxy.com/main/proxies.txt",
    "https://raw.githubusercontent.com/UserR3X/proxy-list/main/online/all.txt",
    "https://raw.githubusercontent.com/hendrikbgr/Free-Proxy-Repo/master/proxy_list.txt",
    "https://raw.githubusercontent.com/fate0/proxylist/master/proxy.list",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/proxy.txt",
    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/http.txt",
    "https://raw.githubusercontent.com/TylerAmesIsGay/proxy-list/main/http_proxies%20(2).txt",
    "https://raw.githubusercontent.com/TylerAmesIsGay/proxy-list/main/http_proxies%20(3).txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",

    # Public API endpoints (7)
    "https://www.proxy-list.download/api/v1/get?type=http",
    "https://www.proxy-list.download/api/v1/get?type=http&anon=elite",
    "https://www.proxy-list.download/api/v1/get?type=http&anon=anonymous",
    "https://www.proxy-list.download/api/v1/get?type=http&anon=transparent",
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all",
    "http://api.proxyscrape.com/?request=displayproxies&proxytype=http",
]

CONNECTION_LIMIT = 100
VALIDATION_URL = "http://httpbin.org/ip"
OUTPUT_FILE = "working_proxies.txt"
TIMEOUT = aiohttp.ClientTimeout(total=8)

sem = asyncio.Semaphore(CONNECTION_LIMIT)
file_lock = asyncio.Lock()  # prevent write race conditions

async def fetch_list(session, url):
    try:
        async with sem:
            async with session.get(url, timeout=TIMEOUT) as resp:
                text = await resp.text()
                return [line.strip() for line in text.splitlines() if line.strip() and not line.startswith("#")]
    except Exception as e:
        print(f"[!] Failed to fetch from {url}: {e}")
        return []

async def append_working_proxy(proxy: str):
    async with file_lock:
        async with aiofiles.open(OUTPUT_FILE, "a") as f:
            await f.write(proxy + "\n")

async def validate_proxy(session, proxy):
    try:
        async with sem:
            async with session.get(VALIDATION_URL, proxy=f"http://{proxy}", timeout=TIMEOUT) as resp:
                if resp.status == 200:
                    print(f"[+] Working: {proxy}")
                    await append_working_proxy(proxy)
    except:
        pass

async def main():
    async with aiohttp.ClientSession() as session:
        print("[*] Fetching proxy sources...")
        results = await asyncio.gather(*(fetch_list(session, url) for url in proxy_sources))
        all_proxies = set(p for group in results for p in group)
        print(f"[+] Total proxies fetched: {len(all_proxies)}")

        print("[*] Validating proxies in parallel...")
        tasks = [validate_proxy(session, proxy) for proxy in all_proxies]
        await asyncio.gather(*tasks)

        print(f"[✓] Validation complete. Working proxies saved to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    asyncio.run(main())
