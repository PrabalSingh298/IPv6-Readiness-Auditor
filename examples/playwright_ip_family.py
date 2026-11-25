"""Run with python -m examples.playwright_ip_family MODE URL."""

import argparse
import json
from dataclasses import asdict

from playwright.sync_api import Error as PlaywrightError, sync_playwright

from backend.measurement.ip_family_proxy import IPFamilyProxy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("dual_stack", "ipv4_only", "ipv6_only"))
    parser.add_argument("url")
    args = parser.parse_args()

    proxy = IPFamilyProxy(args.mode)
    try:
        with proxy, sync_playwright() as playwright:
            browser = playwright.chromium.launch(**proxy.playwright_launch_options())
            try:
                page = browser.new_page()
                response = page.goto(args.url, wait_until="load", timeout=15000)
                print(f"{response.status if response else 'No response'} {page.url}")
            finally:
                browser.close()
    except PlaywrightError as error:
        print(error)
        return 1
    finally:
        for attempt in proxy.connection_attempts:
            print(json.dumps(asdict(attempt)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
