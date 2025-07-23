#!/usr/bin/env python3

# used in fetch_upload_sboms.yml to fetch SBOMs from the Adoptium API and store them in a local directory

import os
import pathlib
import requests
import json
import time
from pathlib import Path
from datetime import datetime

API_URL_BASE = os.environ.get("API_URL_BASE", "https://api.adoptium.net/v3/assets/feature_releases/21/ga")
IMAGE_TYPE = os.environ.get("IMAGE_TYPE", "sbom")
VENDOR = os.environ.get("VENDOR", "eclipse")
HEAP_SIZE = os.environ.get("HEAP_SIZE", "normal")
PAGE_SIZE = int(os.environ.get("PAGE_SIZE", "20"))
PROJECT_ROOT = os.environ.get("PROJECT_ROOT", "Eclipse Temurin")
JAVA_VERSION = os.environ.get("JAVA_VERSION", "JDK 21")
cutoff_date = datetime(2023, 1, 1).date()

def fetch_with_retry(url, retries=3, delay=2):
    for attempt in range(retries):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
    raise Exception(f"Failed to fetch {url} after {retries} attempts.")

def fetch_sboms():
    sbom_dir = Path("sboms")
    sbom_dir.mkdir(exist_ok=True)
    metadata = []

    params = {
        "image_type": IMAGE_TYPE,
        "vendor": VENDOR,
        "heap_size": HEAP_SIZE,
        "page_size": PAGE_SIZE
    }

    response = requests.get(API_URL_BASE, params=params)
    response.raise_for_status()
    data = response.json()

    for asset in data:
        # we stop if the last asset is before the cutoff date
        release_date_str = asset["timestamp"]
        release_date = datetime.fromisoformat(release_date_str.replace("Z", "")).date()

        if release_date < cutoff_date:
            break   

        version = asset["version_data"]["semver"]
        for binary in asset.get("binaries", []):
            os_name = binary["os"]
            arch = binary["architecture"]
            sbom_url = binary.get("package", {}).get("link")

            if not sbom_url:
                print(f"Skipping {version} ({os_name} {arch}) - no SBOM")
                continue

            os_arch = f"{os_name}-{arch}"
            # save path 
            # folder = pathlib.Path("sboms") / os_arch / f"jdk-{version}"
            folder = sbom_dir / os_arch / f"jdk-{version}"
            folder.mkdir(parents=True, exist_ok=True)
            path = folder / "sbom.json"
                
            path.parent.mkdir(parents=True, exist_ok=True)
            print(f"Downloading SBOM for {os_name} {arch} {version}")
            sbom_resp = fetch_with_retry(sbom_url)
            sbom_resp.raise_for_status()
            path.write_text(sbom_resp.text)

            project_name = f"{PROJECT_ROOT} / {JAVA_VERSION} / 21-{os_name}-{arch} / jdk-{version}"
            parent_uuids = {
                "linux aarch64": "3680ceb0-702f-4ebd-811b-adece3f90a27", 
                "linux x64": "6ca279d5-fb01-4957-9f85-de2ed07d3a69", 
                "mac aarch64": "05904a4e-460d-4832-a4d5-4394cbec3c69", 
                "mac x64": "b7752a97-4fdf-4c38-9557-89791eb11191", 
                "windows x64": "14cf7d68-ca5c-4136-91bf-0a7d97ab3980",  
            }
            metadata.append({
                "path": str(path.as_posix()),
                "projectName": project_name,
                "projectVersion": version,
                "parentProject": parent_uuids.get(os_arch, ""),
            })
            
    with open("metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    print("Done. Wrote SBOMs and metadata.json.")

if __name__ == "__main__":
    fetch_sboms()
