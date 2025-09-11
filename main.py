import requests
from bs4 import BeautifulSoup, Tag
import json
import re
import cmd
import sys
from textwrap import dedent

# Load known vulnerable extensions from a JSON database
VULN_DB: dict[str, dict[str, str]] = {
    "Citizen": {"version": "<3.3.1", "cve": "CVE-2025-49579", "exploit": "XSS via HTML injection in Menu.mustache"},
    "CentralAuth": {"version": "<1.39.13|<1.42.7|<1.43.2", "cve": "CVE-2025-6926", "exploit": "Authentication bypass"},
    "UrlShortener": {"version": "<1.42.7|<1.43.2", "cve": "CVE-2025-7056", "exploit": "Stored XSS via improper input neutralization"},
    "Quiz": {"version": "<1.39.13|<1.42.7|<1.43.2", "cve": "CVE-2025-7057", "exploit": "Stored XSS"},
    "MsUpload": {"version": "<2025.0", "cve": "CVE-2025-7362", "exploit": "Stored XSS via msu-continue message"},
    "RefreshSpecial": {"version": "<1.39.11|<1.41.3|<1.42.2", "cve": "CVE-2025-23072", "exploit": "XSS via improper input neutralization"},
    "AbuseFilter": {"version": "<1.39.9|<1.41.3|<1.42.2", "cve": "CVE-2024-47913", "exploit": "Unauthorized filter log access via API"},
    "MediaWikiChat": {"version": "<=1.42.1", "cve": "CVE-2024-40601", "exploit": "CSRF in message sending/settings modification"},
    "CSS": {"version": "<1.39.9|<1.41.3|<1.42.2", "cve": "CVE-2024-47845", "exploit": "Code injection via improper output encoding"},
    "FeaturedFeeds": {"version": "<1.43.1", "cve": "CVE-2025-53502", "exploit": "XSS in feed output"}
}

class WikiExploitCLI(cmd.Cmd):
    prompt = "(WikiExploit) "
    intro = "MediaWiki Extension Exploit Finder. Type 'help' for commands."

    def __init__(self):
        super().__init__()
        self._target_url: str|None = None
        self._extensions: list[dict[str, str]] = []

    @property
    def extensions(self) -> list[dict[str, str]]:
        if self.target_url:
            self._extensions = get_wiki_extensions(self.target_url)
        return self._extensions

    @property
    def target_url(self) -> str:
        if self.target_url:
            return self.target_url
        return ''
    
    @target_url.setter
    def target_url(self, target: str):
        self._target_url = target
    
    def do_set_target(self, target: str):
        """Set the target MediaWiki URL (e.g., set_target https://example.com/wiki)."""
        if not target:
            print("Please provide a target URL.")
            return
        
        self.target_url = target.strip()
        print(f"Target set to: {self.target_url}")
            

    def do_scan(self, *_):
        """Scan the target for installed extensions."""
        if not self.target_url:
            print("No target set. Use 'set_target' first.")
            return
        
        print(f"Scanning {self.target_url} for extensions...")
        if not self.extensions:
            print("No extensions found or error occurred.")
            return
        
        print("Extensions found:")
        for ext in self.extensions:
            print(f"- {ext['name']} (Version: {ext['version']})")

    def do_check_vulns(self, *_):
        """Check for vulnerabilities in detected extensions."""
        if not self.extensions:
            print("No extensions to check. Run 'scan' first.")
            return
        
        if not (vulnerabilities := check_vulnerabilities(self.extensions)):
            print("No known vulnerabilities found.")
            return
        
        print("Vulnerabilities found:")
        for vuln in vulnerabilities:
            print(
                f"Extension: {vuln['extension']}, Version: {vuln['version']}, "
                f"CVE: {vuln['cve']}, Exploit: {vuln['exploit']}"
            )
            

    def do_show_info(self, *_):
        """Show current target and detected extensions."""
        print(f"Target: {self.target_url or 'Not set'}")
        if not self.extensions:
            print("No extensions detected.")
            return
        
        print("Detected extensions:")
        for ext in self.extensions:
            print(f"- {ext['name']} (Version: {ext['version']})")
            

    def do_exit(self, *_):
        """Exit the CLI."""
        return print("Exiting...") or True

    def do_help(self, arg: str):
        """Show available commands."""
        print(dedent(
            """
            Available commands:
            set_target <url>    Set the target MediaWiki URL
            scan               Scan the target for extensions
            check_vulns        Check for vulnerabilities in detected extensions
            show_info          Show current target and extensions
            exit               Exit the CLI
            help               Show this help menu
            """
            )
        )

def get_wiki_extensions(url: str) -> list[dict[str, str]]:
    """Fetch and parse MediaWiki extensions from Special:Version page."""
    try:
        response = requests.get(f"{url}/index.php/Special:Version", timeout=5)
        response.raise_for_status()
    except requests.HTTPError as e:
        print(f"Error fetching extensions: {e}")
        return []
    
    soup = BeautifulSoup(response.text, 'html.parser')
    table = soup.find("table", class_="wikitable")
    
    if not table or not isinstance(table, Tag): # type guard
        print(f'No extension table found!') # notify user
        return []
    
    return [
        {
            'name': name_col.getText(strip=True),
            'version': version_col.getText(strip=True),
        }
        for row in table.findAll('tr') if isinstance(row, Tag)
        for name_col, version_col in row.find_all('td')
    ]


def check_vulnerabilities(extensions: list[dict[str, str]]) -> list[dict[str, str]]:
    """Cross-reference extensions with vulnerability database."""
    return [
        {
            'extension': ext['name'],
            'version': ext['version'],
            'cve': vuln_info['cve'],
            'exploit': vuln_info['exploit'],
        }
        for ext in extensions
        if (vuln_info := VULN_DB.get(ext['name'], {}))
        and re.match(vuln_info['version'], ext['version'])
    ]

if __name__ == "__main__":
    WikiExploitCLI().cmdloop()
