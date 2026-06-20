#!/usr/bin/env python3
"""
Deploy QRadar rules from GitHub repo via REST API.
Supports create, update, and delete operations.
"""

import os
import sys
import json
import glob
import requests
import argparse
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class QRadarRuleDeployer:
    def __init__(self, base_url: str, sec_token: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "SEC": sec_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Version": "19.0"
        })
        self.session.verify = verify_ssl

    def get_existing_rules(self) -> dict:
        """Retrieve all custom rules."""
        url = f"{self.base_url}/api/analytics/rules"
        params = {"filter": "origin=USER", "fields": "id,name,identifier"}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        rules = {}
        for rule in response.json():
            rules[rule.get("identifier", rule["name"])] = rule
        return rules

    def create_rule(self, rule_def: dict) -> dict:
        """Create a new custom rule."""
        url = f"{self.base_url}/api/analytics/rules"
        response = self.session.post(url, json=rule_def)
        response.raise_for_status()
        return response.json()

    def update_rule(self, rule_id: int, rule_def: dict) -> dict:
        """Update an existing rule."""
        url = f"{self.base_url}/api/analytics/rules/{rule_id}"
        response = self.session.put(url, json=rule_def)
        response.raise_for_status()
        return response.json()

    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule by ID."""
        url = f"{self.base_url}/api/analytics/rules/{rule_id}"
        response = self.session.delete(url)
        return response.status_code == 204

    def deploy_rule_file(self, json_path: str) -> dict:
        """Deploy a single rule JSON file."""
        with open(json_path, "r") as f:
            rule_def = json.load(f)
        
        identifier = rule_def.get("identifier", rule_def["name"])
        existing_rules = self.get_existing_rules()
        
        if identifier in existing_rules:
            rule_id = existing_rules[identifier]["id"]
            result = self.update_rule(rule_id, rule_def)
            action = "UPDATE"
        else:
            result = self.create_rule(rule_def)
            action = "CREATE"
        
        print(f"  [{action}] {rule_def['name']} (ID: {result.get('id', 'N/A')})")
        return {"action": action, "rule_id": result.get("id"), "name": rule_def["name"]}

    def deploy_all(self, rules_dir: str) -> dict:
        """Deploy all rule JSON files from directory."""
        all_results = {}
        json_files = glob.glob(os.path.join(rules_dir, "**", "*.json"), recursive=True)
        
        print(f"\n{'='*60}")
        print(f"Deploying {len(json_files)} QRadar rules...")
        print(f"{'='*60}\n")
        
        for json_file in sorted(json_files):
            print(f"Processing: {json_file}")
            try:
                result = self.deploy_rule_file(json_file)
                all_results[json_file] = {"status": "success", "details": result}
            except requests.exceptions.HTTPError as e:
                error_detail = e.response.text if e.response else str(e)
                all_results[json_file] = {"status": "error", "error": error_detail}
                print(f"  [ERROR] {error_detail}")
            except Exception as e:
                all_results[json_file] = {"status": "error", "error": str(e)}
                print(f"  [ERROR] {e}")
        
        return all_results

    def deploy_full_deploy(self, rules_dir: str) -> None:
        """Full deploy with reference set creation."""
        # Create required reference sets
        self._ensure_reference_sets()
        # Deploy rules
        results = self.deploy_all(rules_dir)
        # Trigger deploy
        self._trigger_deploy()
        return results

    def _ensure_reference_sets(self):
        """Create reference sets if they don't exist."""
        ref_sets = [
            {"name": "OWASP_A01_Suspicious_IPs", "element_type": "IP"},
            {"name": "OWASP_SSRF_Indicators", "element_type": "IP"},
            {"name": "OWASP_A03_Supply_Chain_Alerts", "element_type": "IP"},
            {"name": "OWASP_A05_Attacker_IPs", "element_type": "IP"},
            {"name": "OWASP_A07_Targeted_Accounts", "element_type": "ALN"},
            {"name": "OWASP_A10_Crash_Sources", "element_type": "IP"},
        ]
        
        for ref_set in ref_sets:
            url = f"{self.base_url}/api/reference_data/sets"
            try:
                self.session.post(url, json=ref_set)
                print(f"  [REF SET] Ensured: {ref_set['name']}")
            except:
                pass  # Already exists

    def _trigger_deploy(self):
        """Trigger a QRadar deploy to activate rule changes."""
        url = f"{self.base_url}/api/staged_config/deploy_status"
        try:
            response = self.session.post(f"{self.base_url}/api/staged_config/deploy_action", json={"action": "DEPLOY"})
            if response.status_code in (200, 202):
                print("\n  [DEPLOY] Changes deployed to QRadar successfully.")
            else:
                print(f"\n  [DEPLOY] Deploy triggered with status: {response.status_code}")
        except Exception as e:
            print(f"\n  [DEPLOY WARNING] Could not auto-deploy: {e}")
            print("  Please deploy changes manually from QRadar Admin tab.")


def main():
    parser = argparse.ArgumentParser(description="Deploy QRadar rules from GitHub")
    parser.add_argument("--url", required=True, help="QRadar Console URL (https://qradar)")
    parser.add_argument("--token", required=True, help="QRadar API token (SEC header)")
    parser.add_argument("--rules-dir", default="./qradar/rules", help="Directory with rule JSON files")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be deployed")
    parser.add_argument("--full-deploy", action="store_true", help="Create ref sets and trigger deploy")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("[DRY RUN MODE]\n")
        json_files = glob.glob(os.path.join(args.rules_dir, "**", "*.json"), recursive=True)
        for f in sorted(json_files):
            with open(f) as fh:
                rule = json.load(fh)
            print(f"  Would deploy: {rule['name']}")
        return
    
    deployer = QRadarRuleDeployer(args.url, args.token, args.verify_ssl)
    
    if args.full_deploy:
        results = deployer.deploy_full_deploy(args.rules_dir)
    else:
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
