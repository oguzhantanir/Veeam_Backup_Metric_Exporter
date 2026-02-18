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
VEEAM_HOST = os.getenv("VEEAM_HOST", "10.1.0.100")
VEEAM_BASE_URL = f"https://{VEEAM_HOST}:9419/api"
USERNAME = os.getenv("VEEAM_USERNAME", "monitor")
PASSWORD = os.getenv("VEEAM_PASSWORD", "BlaBlaBla")
CLIENT_ID = os.getenv("VEEAM_CLIENT_ID", None)
API_VERSIONS = ["1.2-rev1", "1.2-rev0"] 
SCRAPE_INTERVAL = int(os.getenv("SCRAPE_INTERVAL", "30"))
VEEAM_PORT = int(os.getenv("VEEAM_PORT", "9419"))
TASKSESSION_LOOKBACK = int(os.getenv("TASKSESSION_LOOKBACK", "2000"))
REPLICAPOINT_LOOKBACK = int(os.getenv("REPLICAPOINT_LOOKBACK", "4000"))

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

# ------------ Clear Cache ------------
def clear_all_metrics():
    metrics = [
        veeam_license_instances_total,
        veeam_license_instances_used,
        veeam_license_instances_free,
        veeam_license_expiration_timestamp,
        veeam_license_days_until_expiration,
        veeam_license_status_value,
        veeam_license_info,
        repo_capacity_bytes,
        repo_free_bytes,
        repo_used_bytes,
        repo_used_percent,
        repo_online_status,
        veeam_job_retention_days,
        veeam_job_backup_mode,
        veeam_job_active_full_enabled,
        veeam_job_backup_health_enabled,
        veeam_job_status,
        veeam_job_last_result,
        veeam_job_last_run_timestamp,
        veeam_job_next_run_timestamp,
        veeam_job_objects_count,
        veeam_job_vm_info,
        veeam_job_vm_size_bytes,
        veeam_job_vm_last_result,
        veeam_job_data_size_bytes,
        veeam_job_backup_size_bytes,
        veeam_vm_data_size_bytes,
        veeam_vm_backup_size_bytes,
        veeam_proxies_total,
        veeam_proxy_max_tasks,
        veeam_proxy_failover_to_network,
        veeam_proxy_host_to_proxy_encryption,
        veeam_replication_job_status,
        veeam_replication_job_vm,
        veeam_replication_vm_target_size_bytes,
        veeam_replication_vm_source_size_bytes,
        veeam_replica_total_stored_bytes,
        veeam_replica_points_count,
        veeam_replication_job_points_count
    ]
    
    for metric in metrics:
        try:
            if metric._labelnames:
                for labels in list(metric._metrics.keys()):
                    metric.labels(*labels).set(float("nan"))
            else: 
                metric.set(float("nan"))
        except Exception as e:
            log(f"Error clearing metric {metric._name}: {e}", "ERROR")
            continue

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
            clear_all_metrics()
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

# ============== Replication Metrics ==============
veeam_replication_job_status = Gauge("veeam_replication_job_status", "Replication job status (0=inactive,1=running,2=disabled,3=unknown)", ["job_id","job_name"], registry=REGISTRY)
veeam_replication_job_vm = Gauge("veeam_replication_job_vm", "VMs included in replication jobs (value=1)", ["job_id","job_name","vm_name"], registry=REGISTRY)
veeam_replication_vm_target_size_bytes = Gauge("veeam_replication_vm_target_size_bytes", "Latest ReplicaJob task session transferred bytes for VM (approx last RP size)", ["job_id","job_name","vm_name"], registry=REGISTRY)
veeam_replication_vm_source_size_bytes = Gauge("veeam_replication_vm_source_size_bytes", "Original/source VM size in bytes (declared in job; fallback: latest processedSize/readSize)", ["job_id","job_name","vm_name"], registry=REGISTRY)
veeam_replica_total_stored_bytes = Gauge("veeam_replica_total_stored_bytes", "Sum of transferred bytes across all restore points for each replica (approx total disk usage)", ["replica_id", "job_id", "job_name"], registry=REGISTRY)
veeam_replica_points_count = Gauge("veeam_replica_points_count", "Number of replica restore points per replica", ["replica_id"], registry=REGISTRY)
veeam_replication_job_points_count = Gauge("veeam_replication_job_points_count", "Number of replica restore points per replication job", ["job_id","job_name"], registry=REGISTRY)

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
    states_url = f"{VEEAM_BASE_URL}/v1/jobs/states"
    log("Fetching jobs and states for VM results...")
    states = safe_get_json(states_url, auth).get("data", [])
    session_to_job = {s["sessionId"]: {"id": s["id"], "name": s["name"]}
                      for s in states if s.get("sessionId")}

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
            clear_all_metrics()
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

# ============== Replication Helpers & Fetchers ==============
def is_replication_job(job):
    jtype = (job.get("type") or "").lower()
    return ("replica" in jtype) or ("replication" in jtype)

def fetch_replication_jobs_and_states(auth):
    jobs_url = f"{VEEAM_BASE_URL}/v1/jobs"
    states_url = f"{VEEAM_BASE_URL}/v1/jobs/states"
    jobs_raw = safe_get_json(jobs_url, auth).get("data", [])
    states_raw = safe_get_json(states_url, auth).get("data", [])
    state_map = {s["id"]: s for s in states_raw}

    jobs = []
    vm_declared_size = {}

    for j in jobs_raw:
        if not is_replication_job(j):
            continue
        jid   = j.get("id","unknown")
        jname = j.get("name","unknown")
        st = state_map.get(jid, {})
        status = (st.get("status") or "unknown").lower()
        disabled = 1 if j.get("isDisabled", False) else 0
        if status == "running": status_val = 1
        elif disabled: status_val = 2
        elif status == "inactive": status_val = 0
        else: status_val = 3
        veeam_replication_job_status.labels(jid, jname).set(status_val)

        vms = []
        for vm in j.get("virtualMachines",{}).get("includes",[]):
            inv = vm.get("inventoryObject") or vm
            vm_name = str(inv.get("name","unknown"))
            vms.append(vm_name)
            veeam_replication_job_vm.labels(jid, jname, vm_name).set(1)

            # job config içindeki 'size' -> bytes
            size_candidate = inv.get("size") or vm.get("size")
            b = parse_size_to_bytes(size_candidate)
            if b and b > 0:
                vm_declared_size.setdefault(vm_name, float(b))

        jobs.append({"id": jid, "name": jname, "vms": vms})

    log(f"[replication] jobs: {len(jobs)}")
    return jobs, state_map, vm_declared_size

def fetch_replication_tasks_maps(auth, lookback=TASKSESSION_LOOKBACK):
    params = {
        "sessionTypeFilter":"ReplicaJob",
        "orderColumn":"CreationTime",
        "orderAsc": False,
        "limit": lookback
    }
    
    data = safe_get_json(f"{VEEAM_BASE_URL}/v1/taskSessions", auth, params=params)
    tasks = data.get("data", [])
    vm_latest = {}
    vm_processed = {}
    for t in tasks:
        name = t.get("name")
        prog = t.get("progress") or {}
        tx = prog.get("transferredSize") or prog.get("processedSize") or prog.get("readSize") or 0
        ps = prog.get("processedSize") or prog.get("readSize") or 0
        if name:
            if isinstance(tx, (int,float)) and name not in vm_latest:
                vm_latest[name] = float(tx)
            if isinstance(ps, (int,float)) and name not in vm_processed:
                vm_processed[name] = float(ps)
    log(f"[replication] tasks fetched={len(tasks)}, vm_latest={len(vm_latest)}")
    return vm_latest, vm_processed, tasks

def fetch_replica_point_map_and_counts(auth, lookback=REPLICAPOINT_LOOKBACK):
    params = {"orderColumn":"CreationTime","orderAsc":False,"limit":lookback}
    data = safe_get_json(f"{VEEAM_BASE_URL}/v1/replicaPoints", auth, params=params)
    rps = data.get("data", [])
    rp_to_replica = {}
    counts = {}
    for p in rps:
        rid = p.get("replicaId")
        rp_to_replica[p.get("id")] = rid
        if rid:
            counts[rid] = counts.get(rid, 0) + 1
    log(f"[replication] replicaPoints mapped={len(rp_to_replica)}; replicas with counts={len(counts)}")
    return rp_to_replica, counts

def fetch_replicas_index(auth):
    data = safe_get_json(f"{VEEAM_BASE_URL}/v1/replicas", auth, params={"orderColumn":"Name","orderAsc":True})
    replicas = data.get("data", [])
    rep_index = {}
    rep_ids = set()
    for r in replicas:
        rid = r.get("id")
        if not rid:
            continue
        rep_index[rid] = {"job_id": r.get("jobId","unknown"), "replica_name": r.get("name","unknown")}
        rep_ids.add(rid)
    log(f"[replication] active replicas={len(rep_ids)}")
    return rep_index, rep_ids

def update_replication_metrics(auth):
    jobs, state_map, vm_declared = fetch_replication_jobs_and_states(auth)
    vm_latest, vm_processed, tasks = fetch_replication_tasks_maps(auth)
    current_vm_names = set()
    for j in jobs:
        jid, jname = j["id"], j["name"]
        for vm_name in j["vms"]:
            current_vm_names.add(vm_name)
            tgt_val = vm_latest.get(vm_name, 0.0)
            veeam_replication_vm_target_size_bytes.labels(jid, jname, vm_name).set(tgt_val)
            src_val = vm_declared.get(vm_name, 0.0)
            if not src_val or src_val == 0.0:
                src_val = vm_processed.get(vm_name, 0.0)
            veeam_replication_vm_source_size_bytes.labels(jid, jname, vm_name).set(src_val)
    replicas_index, valid_replica_ids = fetch_replicas_index(auth)
    rp_map, rep_counts_by_replica = fetch_replica_point_map_and_counts(auth)
    job_name_map = {j["id"]: j["name"] for j in jobs}
    totals = {}
    seen_rp = set()
    for t in tasks:
        rp_id = t.get("replicaPointId")
        vm_name = t.get("name","unknown")
        if not rp_id or rp_id in seen_rp:
            continue
        seen_rp.add(rp_id)
        prog = t.get("progress") or {}
        tx = prog.get("transferredSize") or prog.get("processedSize") or prog.get("readSize") or 0.0
        try:
            tx = float(tx)
        except Exception:
            tx = 0.0
        rid = rp_map.get(rp_id)
        if (not rid) or (rid not in valid_replica_ids) or (vm_name not in current_vm_names):
            continue
        totals[rid] = totals.get(rid, 0.0) + tx
    for rid, total in totals.items():
        info = replicas_index.get(rid) or {}
        jid = str(info.get("job_id", "unknown"))
        jname = job_name_map.get(jid, "unknown")
        veeam_replica_total_stored_bytes.labels(str(rid), jid, jname).set(float(total))
    for rid, cnt in rep_counts_by_replica.items():
        if rid in valid_replica_ids:
            veeam_replica_points_count.labels(str(rid)).set(int(cnt))
    job_name_map = {j["id"]: j["name"] for j in jobs}
    per_job = {}
    for rid, cnt in rep_counts_by_replica.items():
        info = replicas_index.get(rid) or {}
        jid = info.get("job_id")
        if not jid:
            continue
        per_job[jid] = per_job.get(jid, 0) + int(cnt)
    for jid, total_cnt in per_job.items():
        jname = job_name_map.get(jid, "unknown")
        veeam_replication_job_points_count.labels(str(jid), str(jname)).set(int(total_cnt))
    log(f"[replication] updated: jobs={len(jobs)}, vm_latest={len(vm_latest)}, replicas_total={len(totals)}, rp_counts={len(rep_counts_by_replica)}")
    
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
            clear_all_metrics()
            time.sleep(5)

        time.sleep(SCRAPE_INTERVAL)



