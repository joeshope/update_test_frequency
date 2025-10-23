import requests
import sys
import os
import json
import time

# --- Configuration ---

# The base host for the Snyk REST API
API_HOST = "https://api.snyk.io"
# The base URL path for the Snyk REST API
API_BASE_URL = f"{API_HOST}/rest"

# The API version to use. This is required by the Snyk REST API.
API_VERSION = "2024-05-23"

# The set of allowed project types for filtering
ALLOWED_TYPES = {
    "nuget", "paket", "cpp", "hex", "golangdep", "govendor", "gomodules",
    "maven", "gradle", "npm", "pnpm", "yarn", "composer", "pip", "pipenv",
    "poetry", "rubygems", "sbt", "cocoapods", "sast", "terraformconfig", 
    "cloudformationconfig", "k8sconfig", "helmconfig", "armconfig", "apk", 
    "deb", "rpm", "linux", "dockerfile",
}

ALL_OPEN_SOURCE = {
    "nuget", "paket", "cpp", "hex", "golangdep", "govendor", "gomodules",
    "maven", "gradle", "npm", "pnpm", "yarn", "composer", "pip", "pipenv",
    "poetry", "rubygems", "sbt", "cocoapods",
}

ALL_IAC = {
    "terraformconfig", "cloudformationconfig", "k8sconfig", 
    "helmconfig", "armconfig",
}

ALL_CONTAINER = {
    "apk", "deb", "rpm", "linux", "dockerfile",
}

ALLOWED_FREQUENCY = {
    "daily", "weekly", "never",
}

RATE_LIMIT_DELAY = 0.05  # (in seconds)

# --- API Functions ---

def get_all_projects(org_id, api_token, types_list=None):
    all_projects = []
    headers = {
        "Authorization": f"token {api_token}",
        "Accept": "application/vnd.api+json"
    }
    
    query_params = {
        "version": API_VERSION,
        "limit": 100
    }
    if types_list:
        query_params["types"] = types_list
    
    base_endpoint = f"{API_BASE_URL}/orgs/{org_id}/projects"
    
    try:
        req = requests.Request('GET', base_endpoint, params=query_params)
        prepared_req = req.prepare()
        next_url = prepared_req.url
    except Exception as e:
        print(f"Error preparing initial request URL: {e}")
        return None

    while next_url:
        try:
            friendly_url = next_url.replace(API_HOST, "")
            print(f"Fetching page: {friendly_url.split('?')[0]}...")
            
            response = requests.get(next_url, headers=headers)
            response.raise_for_status()
            
            response_json = response.json()
            
            projects = response_json.get("data", [])
            if projects:
                all_projects.extend(projects)
            
            next_link = response_json.get("links", {}).get("next")

            if next_link:
                if next_link.startswith("/"):
                    next_url = f"{API_HOST}{next_link}"
                else:
                    next_url = next_link
            else:
                next_url = None

            time.sleep(RATE_LIMIT_DELAY) 

        except requests.exceptions.HTTPError as e:
            print(f"\nError fetching projects: {e}")
            print(f"Response body: {e.response.text}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"\nA network or request error occurred: {e}")
            return None

    return all_projects

def update_project_frequency(org_id, project_id, api_token, frequency):
    update_url = (
        f"{API_BASE_URL}/orgs/{org_id}/projects/{project_id}"
        f"?version={API_VERSION}"
    )
    
    headers = {
        "Authorization": f"token {api_token}",
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json"
    }
    
    payload = {
        "data": {
            "type": "project",
            "id": project_id,
            "relationships": {},
            "attributes": {
                "test_frequency": frequency
            }
        }
    }

    try:
        response = requests.patch(update_url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        
        if response.status_code == 200:
            return True
        else:
            print(f"  > Received unexpected status code: {response.status_code}")
            return False
            
    except requests.exceptions.HTTPError as e:
        # Handle 429 Too Many Requests specifically
        if e.response.status_code == 429:
            print(f"    > RATE LIMIT HIT. Pausing for 10 seconds...")
            time.sleep(10) # Pause for 10s if we get rate limited
            return "retry" # Return a special string to signal a retry
        
        print(f"  > Error updating project: {e}")
        print(f"  > Response body: {e.response.text}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"  > A network or request error occurred: {e}")
        return False

# --- Main Execution ---

def main():
    print("Snyk Project Test Frequency Updater")
    print("=" * 34 + "\n")

    api_token = os.environ.get("SNYK_TOKEN")
    if not api_token:
        api_token = input("Enter your Snyk API token (or set SNYK_TOKEN env var): ")

    org_id = input("Enter your Organization ID: ")

    print("Allowed frequency:", ", ".join(ALLOWED_FREQUENCY))
    print("Note: SAST and IAC configurations can only be set to weekly or never. Contact your account team if you would like to test daily.")
    frequency = input("Enter your desired test frequency: ")

    if not api_token or not org_id or not frequency:
        print("\nAPI token, Frequency, and Organization ID are required. Exiting.")
        sys.exit(1)

    use_all_types = "--all-types" in sys.argv
    use_all_sca = "--sca" in sys.argv
    use_all_iac = "--iac" in sys.argv
    use_all_container = "--container" in sys.argv
    selected_types = []

    if use_all_types:
        print("\n--all-types flag detected. Filtering by all allowed project types.")
        selected_types = list(ALLOWED_TYPES)
    elif use_all_sca:
        print("\n--sca flag detected. Filtering by open source project types.")
        selected_types = list(ALL_OPEN_SOURCE)
    elif use_all_sca:
        print("\n--iac flag detected. Filtering by IAC project types.")
        selected_types = list(ALL_IAC)
    elif use_all_sca:
        print("\n--container flag detected. Filtering by container project types.")
        selected_types = list(ALL_CONTAINER)
    else:
        print("\n--- Project Type Filter (Optional) ---")
        print("Allowed types:", ", ".join(sorted(ALLOWED_TYPES)))
        type_input = input("Enter desired types (comma-separated), or press Enter to skip: ")

        if type_input.strip():
            user_types = [t.strip().lower() for t in type_input.split(',')]
            invalid_types = []
            
            for t in user_types:
                if t in ALLOWED_TYPES:
                    selected_types.append(t)
                elif t:
                    invalid_types.append(t)
            
            if invalid_types:
                print(f"\nWarning: Ignoring invalid types: {', '.join(invalid_types)}")
            
            if selected_types:
                print(f"Filtering by types: {', '.join(selected_types)}")
            else:
                print("No valid types selected. Fetching all project types.")
        else:
            print("No filter specified. Fetching all project types.")

    print(f"\nFetching projects for Organization ID: {org_id}...")
    projects = get_all_projects(org_id, api_token, selected_types)
    
    if projects is None:
        print("Failed to retrieve projects. Exiting.")
        sys.exit(1)
        
    project_count = len(projects)
    print(f"\nFound {project_count} matching projects.")

    if project_count == 0:
        print("No projects to update. Exiting.")
        sys.exit(0)

    print("\nStarting project updates to frequency...")
    updated_count = 0
    failed_count = 0
    i = 0
    while i < len(projects):
        project = projects[i]
        project_id = project.get("id")
        project_name = project.get("attributes", {}).get("name", "Unknown Name")
        
        current_index_display = i + 1
        
        if not project_id:
            print(f"  [{current_index_display}/{project_count}] Skipping item, no project ID found.")
            failed_count += 1
            i += 1 # Move to the next project
            continue

        print(f"  [{current_index_display}/{project_count}] Updating project: {project_name} (ID: {project_id})")
        
        result = update_project_frequency(org_id, project_id, api_token, frequency)
        
        if result is True:
            print(f"    > Success.")
            updated_count += 1
            i += 1 # Move to the next project
        elif result == "retry":
            print(f"    > Retrying update for project {project_id}...")
        else: # Result is False
            print(f"    > Failed.")
            failed_count += 1
            i += 1 # Move to the next project

        time.sleep(RATE_LIMIT_DELAY)

    print("\n--- Update Complete ---")
    print(f"Successfully updated: {updated_count}")
    print(f"Failed to update:   {failed_count}")
    print(f"Total projects:     {project_count}")
    print("-------------------------")

if __name__ == "__main__":
    main()