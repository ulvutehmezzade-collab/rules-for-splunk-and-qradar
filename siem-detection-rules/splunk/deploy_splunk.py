#!/usr/bin/env python3
"""
Deploy Splunk correlation searches from GitHub repo via REST API.
Supports create, update, and delete operations.
"""

import os
import sys
import json
import glob
import hashlib
import requests
import argparse
import configparser
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class SplunkRuleDeployer:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Output-Mode": "json"
        })
        self.session.verify = verify_ssl

    def get_existing_searches(self) -> dict:
        """Retrieve all existing correlation searches."""
        url = f"{self.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches"
        params = {"count": 0, "search": "action.correlationsearch.enabled=1"}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        searches = {}
        for entry in response.json().get("entry", []):
            searches[entry["name"]] = entry
        return searches

    def deploy_search(self, conf_path: str) -> dict:
        """Deploy a single savedsearches.conf stanza."""
        config = configparser.ConfigParser(interpolation=None)
        config.read(conf_path)
        
        results = {}
        for stanza_name in config.sections():
            params = dict(config[stanza_name])
            params["name"] = stanza_name
            
            # Check if search exists
            existing = self.get_existing_searches()
            
            if stanza_name in existing:
                # Update existing
                url = f"{self.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{requests.utils.quote(stanza_name, safe='')}"
                del params["name"]
                response = self.session.post(url, data=params)
            else:
                # Create new
                url = f"{self.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches"
                response = self.session.post(url, data=params)
            
            response.raise_for_status()
            results[stanza_name] = {
                "status": "updated" if stanza_name in existing else "created",
                "http_code": response.status_code
            }
            print(f"  [{'UPDATE' if stanza_name in existing else 'CREATE'}] {stanza_name}")
        
        return results

    def deploy_all(self, rules_dir: str) -> dict:
        """Deploy all rules from directory."""
        all_results = {}
        conf_files = glob.glob(os.path.join(rules_dir, "**", "*.conf"), recursive=True)
        
        print(f"\n{'='*60}")
        print(f"Deploying {len(conf_files)} Splunk rule files...")
        print(f"{'='*60}\n")
        
        for conf_file in sorted(conf_files):
            print(f"Processing: {conf_file}")
            try:
                result = self.deploy_search(conf_file)
                all_results[conf_file] = {"status": "success", "details": result}
            except Exception as e:
                all_results[conf_file] = {"status": "error", "error": str(e)}
                print(f"  [ERROR] {e}")
        
        return all_results

    def delete_search(self, search_name: str) -> bool:
        """Delete a correlation search."""
        url = f"{self.base_url}/servicesNS/nobody/SplunkEnterpriseSecuritySuite/saved/searches/{requests.utils.quote(search_name, safe='')}"
        response = self.session.delete(url)
        return response.status_code == 200


def main():
    parser = argparse.ArgumentParser(description="Deploy Splunk rules from GitHub")
    parser.add_argument("--url", required=True, help="Splunk Management URL (https://splunk:8089)")
    parser.add_argument("--token", required=True, help="Splunk API token")
    parser.add_argument("--rules-dir", default="./splunk/correlation_searches", help="Directory with .conf files")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deployed without making changes")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("[DRY RUN MODE] No changes will be made.\n")
        conf_files = glob.glob(os.path.join(args.rules_dir, "**", "*.conf"), recursive=True)
        for f in sorted(conf_files):
            config = configparser.ConfigParser(interpolation=None)
            config.read(f)
            for stanza in config.sections():
                print(f"  Would deploy: {stanza}")
        return
    
    deployer = SplunkRuleDeployer(args.url, args.token, args.verify_ssl)
    results = deployer.deploy_all(args.rules_dir)
    
    # Summary
    success = sum(1 for r in results.values() if r["status"] == "success")
    errors = sum(1 for r in results.values() if r["status"] == "error")
    print(f"\n{'='*60}")
    print(f"Deployment Complete: {success} succeeded, {errors} failed")
    print(f"{'='*60}")
    
    if errors > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
