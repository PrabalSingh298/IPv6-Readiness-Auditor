from playwright.sync_api import sync_playwright


def main() -> None:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        page.set_content("<title>IPv6 Readiness Auditor</title><h1>Browser launch works</h1>")

        title = page.title()
        heading = page.locator("h1").inner_text()

        print(f"Chromium launched: {browser.version}")
        print(f"Document title: {title}")
        print(f"Heading: {heading}")

        browser.close()


if __name__ == "__main__":
    main()
