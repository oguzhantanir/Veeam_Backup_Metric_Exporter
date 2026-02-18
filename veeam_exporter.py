#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
import socket
import requests
import urllib3
import os
import re
from datetime import datetime, timezone
from collections import defaultdict
from prometheus_client import start_http_server, Gauge, CollectorRegistry

# ============== Config ==============
VEEAM_HOST = os.getenv("VEEAM_HOST", "10.6.0.66")
VEEAM_BASE_URL = f"https://{VEEAM_HOST}:9419/api"
USERNAME = os.getenv("VEEAM_USERNAME", "monitor")
PASSWORD = os.getenv("VEEAM_PASSWORD", "rLyYr735:146")
CLIENT_ID = os.getenv("VEEAM_CLIENT_ID", None)  # gerekirse: "VeeamBackupService"
API_VERSIONS = ["1.2-rev1", "1.2-rev0"]        # deneme sırası
SCRAPE_INTERVAL = int(os.getenv("SCRAPE_INTERVAL", "30"))
VEEAM_PORT = int(os.getenv("VEEAM_PORT", "9419"))

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============== Logging ==============
def log(msg, level="INFO"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [{level}] {msg}", flush=True)

# ============== Connectivity ==============
def check_connectivity(host, port=9419, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            log(f"Connection to {host}:{port} successful.")
            return True
    except Exception as e:
        log(f"Connection to {host}:{port} failed: {e}", "ERROR")
        return False

# ============== Auth / HTTP ==============
class AuthError(Exception):
    pass

def safe_request(method, url, auth_token=None, session_id=None, api_version=API_VERSIONS[0], **kwargs):
    delay = 5
    headers = kwargs.pop("headers", {})
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    elif session_id:
        headers["X-RestSvcSessionId"] = session_id
    headers["x-api-version"] = api_version
    kwargs["headers"] = headers
    kwargs["verify"] = False
    kwargs["timeout"] = kwargs.get("timeout", 20)

    while True:
        try:
            r = requests.request(method, url, **kwargs)
            if r.status_code in (400, 401, 403):
                error_msg = f"{r.status_code} - {r.text}"
                log(f"Auth error: {error_msg}", "ERROR")
                raise AuthError(error_msg)
            r.raise_for_status()
            return r
        except AuthError:
            raise
        except Exception as e:
            log(f"Request error: {e}", "ERROR")
            log(f"Retrying in {delay}s...")
            time.sleep(delay)
            delay = min(delay * 2, 300)

def get_oauth_token():
    token_url = f"{VEEAM_BASE_URL}/oauth2/token"
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    data = {"grant_type": "password", "username": USERNAME, "password": PASSWORD}
    if CLIENT_ID:
        data["client_id"] = CLIENT_ID

    for api_version in API_VERSIONS:
        log(f"Trying OAuth2 with x-api-version: {api_version}")
        try:
            r = safe_request("post", token_url, headers={**headers, "x-api-version": api_version}, data=data)
            access_token = r.json().get("access_token")
            if access_token:
                log(f"OAuth2 token obtained successfully with x-api-version: {api_version}")
                return {"type": "oauth", "value": access_token, "api_version": api_version}
            raise Exception("No access_token in response")
        except Exception as e:
            log(f"OAuth2 failed with x-api-version {api_version}: {e}", "ERROR")
            continue
    raise Exception("OAuth2 failed for all API versions")

def get_session_id_fallback():
    session_url = f"{VEEAM_BASE_URL}/session"
    auth = requests.auth.HTTPBasicAuth(USERNAME, PASSWORD)
    headers = {"Accept": "application/json"}

    for api_version in API_VERSIONS:
        log(f"Trying session-based auth with x-api-version: {api_version}")
        try:
            r = safe_request("post", session_url, auth=auth, headers={**headers, "x-api-version": api_version})
            session_id = r.headers.get("X-RestSvcSessionId")
            if session_id:
                log(f"Session ID obtained via fallback with x-api-version: {api_version}")
                return {"type": "session", "value": session_id, "api_version": api_version}
            raise Exception("No session ID in response")
        except Exception as e:
            log(f"Fallback auth failed with x-api-version {api_version}: {e}", "ERROR")
            continue
    raise Exception("Session-based auth failed for all API versions")

def get_auth():
    try:
        return get_oauth_token()
    except:
        try:
            return get_session_id_fallback()
        except:
            raise Exception("Both auth methods failed")

def safe_get_json(url, auth, params=None):
    headers = {"Accept": "application/json"}
    r = safe_request(
        "get", url,
        auth_token=auth["value"] if auth["type"] == "oauth" else None,
        session_id=auth["value"] if auth["type"] == "session" else None,
        api_version=auth["api_version"],
        headers=headers, params=params or {},
    )
    return r.json()

# ============== Only LICENSE Metrics ==============
REGISTRY = CollectorRegistry()

veeam_license_instances_total = Gauge("veeam_license_instances_total", "Licensed instances total", registry=REGISTRY)
veeam_license_instances_used = Gauge("veeam_license_instances_used", "Used instances", registry=REGISTRY)
veeam_license_instances_free = Gauge("veeam_license_instances_free", "Free (remaining) instances", registry=REGISTRY)
veeam_license_expiration_timestamp = Gauge("veeam_license_expiration_timestamp", "License expiration time (unix epoch seconds)", registry=REGISTRY)
veeam_license_days_until_expiration = Gauge("veeam_license_days_until_expiration", "Days until license expiration (negative if expired)", registry=REGISTRY)
veeam_license_status_value = Gauge("veeam_license_status_value", "License status (1=Valid, 0=NotValid/Expired/Unknown)", registry=REGISTRY)
veeam_license_info = Gauge("veeam_license_info", "Static license info (edition, type, status as labels)", ["edition", "type", "status"], registry=REGISTRY)

# ============== Repository Metrics ==============
repo_capacity_bytes = Gauge("veeam_repository_capacity_bytes", "Repository total capacity (bytes)", ["id", "name", "type", "host"], registry=REGISTRY)
repo_free_bytes = Gauge("veeam_repository_free_bytes", "Repository free space (bytes)", ["id", "name", "type", "host"], registry=REGISTRY)
repo_used_bytes = Gauge("veeam_repository_used_bytes", "Repository used space (bytes)", ["id", "name", "type", "host"], registry=REGISTRY)
repo_used_percent = Gauge("veeam_repository_used_percent", "Repository used percent (0-100)", ["id", "name", "type", "host"], registry=REGISTRY)
repo_online_status = Gauge("veeam_repository_online_status", "Repository online status (1=online,0=offline)", ["id", "name", "type", "host"], registry=REGISTRY)

# ============== Job Metrics ==============
veeam_job_retention_days = Gauge("veeam_job_retention_days", "Job retention policy days", ["id","name"], registry=REGISTRY)
veeam_job_backup_mode = Gauge("veeam_job_backup_mode", "Job backup mode (1=enabled with this mode)", ["id","name","mode"], registry=REGISTRY)
veeam_job_active_full_enabled = Gauge("veeam_job_active_full_enabled", "Job active full backups enabled (1/0)", ["id","name"], registry=REGISTRY)
veeam_job_backup_health_enabled = Gauge("veeam_job_backup_health_enabled", "Job backup health check enabled (1/0)", ["id","name"], registry=REGISTRY)

veeam_job_status = Gauge("veeam_job_status", "Job status (0=inactive,1=running,2=disabled,3=unknown)", ["id","name","type","repository"], registry=REGISTRY)
veeam_job_last_result = Gauge("veeam_job_last_result", "Job last result (0=Success,1=Warning,2=Failed,3=None/Unknown)", ["id","name","type"], registry=REGISTRY)
veeam_job_last_run_timestamp = Gauge("veeam_job_last_run_timestamp","Job last run timestamp (epoch)", ["id","name"], registry=REGISTRY)
veeam_job_next_run_timestamp = Gauge("veeam_job_next_run_timestamp","Job next run timestamp (epoch)", ["id","name"], registry=REGISTRY)
veeam_job_objects_count = Gauge("veeam_job_objects_count","Number of objects in job", ["id","name","repository"], registry=REGISTRY)

veeam_job_vm_info = Gauge("veeam_job_vm_info", "VMs included in backup jobs (value=1)", ["job_id","job_name","vm_name","vm_host","object_id"], registry=REGISTRY)
veeam_job_vm_size_bytes = Gauge("veeam_job_vm_size_bytes", "VM size in bytes as seen by job", ["job_id","job_name","vm_name"], registry=REGISTRY)

veeam_job_vm_last_result = Gauge("veeam_job_vm_last_result", "Last job result per VM (0=Success,1=Warning,2=Failed,3=Other)", ["job_id","job_name","vm_name"], registry=REGISTRY)

# ============== Job Repository Usage Metrics ==============
veeam_job_data_size_bytes = Gauge("veeam_job_data_size_bytes", "Total source data size for a job (bytes)", ["job_name","repository"], registry=REGISTRY)
veeam_job_backup_size_bytes = Gauge("veeam_job_backup_size_bytes", "Total repository storage used for a job (bytes, after dedup/compression)", ["job_name","repository"], registry=REGISTRY)

# ============== VM Repository Usage Metrics ==============
veeam_vm_data_size_bytes = Gauge("veeam_vm_data_size_bytes", "Total processed source data size for a VM (bytes)", ["vm_name","job_name","repository"], registry=REGISTRY)
veeam_vm_backup_size_bytes = Gauge("veeam_vm_backup_size_bytes", "Total repository storage used for a VM (bytes, after dedup/compression)", ["vm_name","job_name","repository"], registry=REGISTRY)

def parse_iso8601_to_epoch(ts: str):
    if not ts:
        return None
    try:
        # 2024-12-31T00:00:00Z
        return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
    except Exception:
        try:
            return int(time.mktime(time.strptime(ts.replace(".000", ""), "%Y-%m-%dT%H:%M:%SZ")))
        except Exception:
            return None

def fetch_license(auth):
    url = f"{VEEAM_BASE_URL}/v1/license"
    log("Fetching license info...")
    data = safe_get_json(url, auth)

    # ---- edition/type/status label metric ----
    edition = str(data.get("edition") or "unknown")
    ltype   = str(data.get("type") or "unknown")
    status  = str(data.get("status") or "unknown")
    veeam_license_info.labels(edition=edition, type=ltype, status=status).set(1.0)

    # ---- status numeric ----
    status_val = 1.0 if status.lower() == "valid" else 0.0
    veeam_license_status_value.set(status_val)

    # ---- expiration ----
    exp_ts = parse_iso8601_to_epoch(data.get("expirationDate"))
    if exp_ts is not None:
        veeam_license_expiration_timestamp.set(exp_ts)
        now = int(time.time())
        days_left = (exp_ts - now) / 86400.0
        veeam_license_days_until_expiration.set(days_left)
    else:
        veeam_license_expiration_timestamp.set(0)
        veeam_license_days_until_expiration.set(float("nan"))

    # ---- instance license summary ----
    inst = data.get("instanceLicenseSummary") or {}
    total = inst.get("licensedInstancesNumber")
    used = inst.get("usedInstancesNumber")

    total = int(total) if isinstance(total, (int, float)) else 0
    used = int(used) if isinstance(used, (int, float)) else 0
    free = max(total - used, 0)

    veeam_license_instances_total.set(total)
    veeam_license_instances_used.set(used)
    veeam_license_instances_free.set(free)

    log(f"License metrics updated: edition={edition}, type={ltype}, status={status}, total={total}, used={used}, exp_ts={exp_ts}")

def fetch_repositories(auth):
    url = f"{VEEAM_BASE_URL}/v1/backupInfrastructure/repositories/states"
    log("Fetching repository states...")
    data = safe_get_json(url, auth)
    repos = data.get("data", [])

    for r in repos:
        rid = r.get("id", "unknown")
        name = r.get("name", "unknown")
        rtype = r.get("type", "unknown")
        host  = r.get("hostName", "unknown")

        cap_gb = float(r.get("capacityGB") or 0)
        free_gb = float(r.get("freeGB") or 0)
        used_gb = float(r.get("usedSpaceGB") or 0)
        online = 1.0 if r.get("isOnline", False) else 0.0

        # Byte'a çevir
        cap_b = cap_gb * 1024**3
        free_b = free_gb * 1024**3
        used_b = used_gb * 1024**3
        used_pct = (used_gb / cap_gb * 100) if cap_gb > 0 else 0

        repo_capacity_bytes.labels(rid, name, rtype, host).set(cap_b)
        repo_free_bytes.labels(rid, name, rtype, host).set(free_b)
        repo_used_bytes.labels(rid, name, rtype, host).set(used_b)
        repo_used_percent.labels(rid, name, rtype, host).set(used_pct)
        repo_online_status.labels(rid, name, rtype, host).set(online)

    log(f"Repository metrics updated: {len(repos)} repos")

# ============== Proxy Metrics ==============
veeam_proxies_total = Gauge("veeam_proxies_total", "Total number of proxies", registry=REGISTRY)
veeam_proxy_max_tasks = Gauge("veeam_proxy_max_tasks", "Proxy maximum task count", ["id","name","type","transportMode"], registry=REGISTRY)
veeam_proxy_failover_to_network = Gauge("veeam_proxy_failover_to_network", "Proxy failover to network (1=true,0=false)", ["id","name"], registry=REGISTRY)
veeam_proxy_host_to_proxy_encryption = Gauge("veeam_proxy_host_to_proxy_encryption", "Proxy host-to-proxy encryption (1=true,0=false)", ["id","name"], registry=REGISTRY)

def fetch_proxies(auth):
    url = f"{VEEAM_BASE_URL}/v1/backupInfrastructure/proxies"
    log("Fetching proxy states...")
    data = safe_get_json(url, auth)
    proxies = data.get("data", [])

    veeam_proxies_total.set(len(proxies))

    for p in proxies:
        pid   = p.get("id","unknown")
        name  = p.get("name","unknown")
        ptype = p.get("type","unknown")
        server = p.get("server", {})
        tmode = server.get("transportMode","unknown")
        max_tasks = int(server.get("maxTaskCount") or 0)
        failover  = 1.0 if server.get("failoverToNetwork") else 0.0
        encrypt   = 1.0 if server.get("hostToProxyEncryption") else 0.0

        veeam_proxy_max_tasks.labels(pid,name,ptype,tmode).set(max_tasks)
        veeam_proxy_failover_to_network.labels(pid,name).set(failover)
        veeam_proxy_host_to_proxy_encryption.labels(pid,name).set(encrypt)

    log(f"Proxy metrics updated: {len(proxies)} proxies")

def parse_size_to_bytes(size_str):
    if not size_str:
        return 0
    try:
        num, unit = size_str.split()
        num = float(num.replace(",", "."))
        unit = unit.upper()
        if unit.startswith("TB"): return num * 1024**4
        if unit.startswith("GB"): return num * 1024**3
        if unit.startswith("MB"): return num * 1024**2
        if unit.startswith("KB"): return num * 1024
        return num
    except Exception:
        return 0

def fetch_jobs(auth):
    jobs_url = f"{VEEAM_BASE_URL}/v1/jobs"
    states_url = f"{VEEAM_BASE_URL}/v1/jobs/states"

    log("Fetching jobs...")
    jobs = safe_get_json(jobs_url, auth).get("data", [])
    states = safe_get_json(states_url, auth).get("data", [])
    state_map = {s["id"]: s for s in states}

    for job in jobs:
        jid   = job.get("id","unknown")
        name  = job.get("name","unknown")
        jtype = job.get("type","unknown")

        # --- VMs included in job ---
        vms = job.get("virtualMachines",{}).get("includes",[])
        for vm in vms:
            inv = vm.get("inventoryObject") or vm  # inventoryObject varsa onu, yoksa vm dict'i al
            vm_name = inv.get("name","unknown")
            vm_host = inv.get("hostName","unknown")
            vm_id   = inv.get("objectId","unknown")
            size    = parse_size_to_bytes(vm.get("size"))

            veeam_job_vm_info.labels(jid,name,vm_name,vm_host,vm_id).set(1)
            veeam_job_vm_size_bytes.labels(jid,name,vm_name).set(size)

        # ---- job config (static) ----
        retention = job.get("storage",{}).get("retentionPolicy",{}).get("quantity")
        if retention is not None:
            veeam_job_retention_days.labels(jid,name).set(retention)

        mode = job.get("storage",{}).get("advancedSettings",{}).get("backupModeType")
        if mode:
            veeam_job_backup_mode.labels(jid,name,mode).set(1)

        active_full = job.get("storage",{}).get("advancedSettings",{}).get("activeFulls",{}).get("isEnabled",False)
        veeam_job_active_full_enabled.labels(jid,name).set(1 if active_full else 0)

        health = job.get("storage",{}).get("advancedSettings",{}).get("backupHealth",{}).get("isEnabled",False)
        veeam_job_backup_health_enabled.labels(jid,name).set(1 if health else 0)

        # ---- job states (runtime) ----
        st = state_map.get(jid)
        if st:
            repo_name = st.get("repositoryName","unknown")

            status = st.get("status","unknown").lower()
            if status == "running": status_val=1
            elif job.get("isDisabled",False): status_val=2
            elif status == "inactive": status_val=0
            else: status_val=3
            veeam_job_status.labels(jid,name,jtype,repo_name).set(status_val)

            last = (st.get("lastResult") or "unknown").lower()
            if last == "success": lr=0
            elif last == "warning": lr=1
            elif last == "failed": lr=2
            else: lr=3
            veeam_job_last_result.labels(jid,name,jtype).set(lr)

            last_run = parse_iso8601_to_epoch(st.get("lastRun"))
            if last_run:
                veeam_job_last_run_timestamp.labels(jid,name).set(last_run)

            next_run = parse_iso8601_to_epoch(st.get("nextRun"))
            if next_run:
                veeam_job_next_run_timestamp.labels(jid,name).set(next_run)

            objects_count = st.get("objectsCount")
            if objects_count is not None:
                veeam_job_objects_count.labels(jid,name,repo_name).set(objects_count)

    log(f"Job metrics updated: {len(jobs)} jobs")

def fetch_job_vm_results(auth):
    # Önce job states ile sessionId eşleşmesi çıkar
    states_url = f"{VEEAM_BASE_URL}/v1/jobs/states"
    log("Fetching jobs and states for VM results...")
    states = safe_get_json(states_url, auth).get("data", [])
    session_to_job = {s["sessionId"]: {"id": s["id"], "name": s["name"]}
                      for s in states if s.get("sessionId")}

    # Task sessions (VM bazlı sonuçlar)
    tasks_url = f"{VEEAM_BASE_URL}/v1/taskSessions"
    params = {"typeFilter": "Backup", "sessionTypeFilter": "BackupJob", "limit": 200}
    data = safe_get_json(tasks_url, auth, params=params)
    tasks = data.get("data", [])

    for t in tasks:
        sid = t.get("sessionId")
        job = session_to_job.get(sid)
        if not job:
            continue

        job_id = job["id"]
        job_name = job["name"]
        vm_name = t.get("name", "unknown")

        result = (t.get("result") or {}).get("result", "unknown").lower()
        if result == "success":
            r = 0
        elif result == "warning":
            r = 1
        elif result == "failed":
            r = 2
        else:
            r = 3

        veeam_job_vm_last_result.labels(job_id, job_name, vm_name).set(r)

    log(f"VM-level job results updated: {len(tasks)} task sessions")

# --------- MAP Yardımcıları (tek seferlik) ----------
def fetch_repositories_map(auth):
    url = f"{VEEAM_BASE_URL}/v1/backupInfrastructure/repositories"
    data = safe_get_json(url, auth)
    repos = {}
    for r in data.get("data", []):
        repos[r["id"]] = r.get("name", "unknown")
    return repos

def fetch_job_states_map(auth):
    data = safe_get_json(f"{VEEAM_BASE_URL}/v1/jobs/states", auth)
    return {j["name"]: j.get("repositoryName", "unknown") for j in data.get("data", [])}

# --------- Job repo usage (map parametreli) ----------
def fetch_job_repo_usage(auth, repos_map, job_states):
    log("Fetching job repository usage...")
    backups = safe_get_json(f"{VEEAM_BASE_URL}/v1/backups", auth).get("data", [])

    for b in backups:
        backup_id = b.get("id")
        job_name  = b.get("name", "unknown")
        repo_id   = b.get("repositoryId", "unknown")
        repo_name = repos_map.get(repo_id, "unknown")
        if repo_name == "unknown":
            repo_name = job_states.get(job_name, "unknown")

        files = safe_get_json(f"{VEEAM_BASE_URL}/v1/backups/{backup_id}/backupFiles", auth).get("data", [])
        total_data   = sum(int(f.get("dataSize") or 0) for f in files)
        total_backup = sum(int(f.get("backupSize") or 0) for f in files)

        veeam_job_data_size_bytes.labels(job_name, repo_name).set(total_data)
        veeam_job_backup_size_bytes.labels(job_name, repo_name).set(total_backup)

    log(f"Job repo usage metrics updated: {len(backups)} backups")

# --------- VM repo usage (map parametreli) ----------
def fetch_vm_repository_usage(auth, repos_map, job_states):
    log("Fetching VM repository usage...")

    backups = safe_get_json(f"{VEEAM_BASE_URL}/v1/backups", auth).get("data", [])
    log(f"Found {len(backups)} backups")

    vm_totals = defaultdict(lambda: {"data":0,"backup":0,"job":"unknown","repo":"unknown"})

    for b in backups:
        backup_id = b.get("id")
        job_name  = b.get("name","unknown")
        repo_id   = b.get("repositoryId","unknown")
        repo_name = repos_map.get(repo_id,"unknown")
        if repo_name == "unknown":
            repo_name = job_states.get(job_name,"unknown")

        try:
            files = safe_get_json(f"{VEEAM_BASE_URL}/v1/backups/{backup_id}/backupFiles", auth).get("data", [])
        except Exception as e:
            log(f"Failed to fetch backup files for job {job_name}: {e}", "ERROR")
            continue

        for f in files:
            fname = (f.get("name") or "").lower()
            match = re.search(r'([^/]+)\.vm', fname)
            if match:
                vm_name = match.group(1)
            else:
                vm_name = "unknown"

            vm_totals[vm_name]["data"]   += int(f.get("dataSize") or 0)
            vm_totals[vm_name]["backup"] += int(f.get("backupSize") or 0)
            vm_totals[vm_name]["job"]     = job_name
            vm_totals[vm_name]["repo"]    = repo_name

    for vm, vals in vm_totals.items():
        veeam_vm_data_size_bytes.labels(vm, vals["job"], vals["repo"]).set(vals["data"])
        veeam_vm_backup_size_bytes.labels(vm, vals["job"], vals["repo"]).set(vals["backup"])

    log(f"VM repository usage metrics updated: {len(vm_totals)} VMs")

# ============== Main ==============
if __name__ == "__main__":
    log("Starting Veeam LICENSE Exporter on :8000/metrics (GET-only)")
    start_http_server(8000, registry=REGISTRY)

    if not check_connectivity(VEEAM_HOST, VEEAM_PORT):
        log("Exiting exporter due to connectivity issue.", "ERROR")
        raise SystemExit(1)

    auth = get_auth()

    while True:
        try:
            fetch_license(auth)
            fetch_repositories(auth)
            fetch_proxies(auth)
            fetch_jobs(auth)
            fetch_job_vm_results(auth)

            # ---- Map'leri tek sefer çek ----
            repos_map = fetch_repositories_map(auth)
            job_states = fetch_job_states_map(auth)

            # ---- Map'leri kullanan fonksiyonlar ----
            fetch_job_repo_usage(auth, repos_map, job_states)
            fetch_vm_repository_usage(auth, repos_map, job_states)

        except AuthError:
            log("Auth expired/invalid, renewing...", "INFO")
            auth = get_auth()
        except Exception as e:
            log(f"Unexpected error: {e}", "ERROR")
            time.sleep(5)

        time.sleep(SCRAPE_INTERVAL)
