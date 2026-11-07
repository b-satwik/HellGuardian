import os
import sqlite3
import json
import time
from typing import Dict, Any, List, Optional
from cloud_backend.config import config

class CloudDatabase:
    """
    Persistent Database Manager for HellGuardian Cloud Telemetry.
    Uses SQLite with WAL mode by default, providing high performance, zero external setup,
    and portability across local testing, Docker, Render, Railway, and Fly.io.
    Supports PostgreSQL if DATABASE_URL starts with postgres:// or postgresql://.
    """
    def __init__(self, db_url: str = None):
        self.db_url = db_url or config.DATABASE_URL
        self.is_postgres = self.db_url.startswith("postgresql://") or self.db_url.startswith("postgres://")
        
        if self.is_postgres:
            # Clean postgres:// to postgresql:// if needed
            if self.db_url.startswith("postgres://"):
                self.db_url = self.db_url.replace("postgres://", "postgresql://", 1)
            self._init_postgres()
        else:
            # SQLite path resolution
            if self.db_url.startswith("sqlite:///"):
                self.sqlite_path = self.db_url.replace("sqlite:///", "")
            else:
                self.sqlite_path = self.db_url
            self.sqlite_path = os.path.abspath(self.sqlite_path)
            os.makedirs(os.path.dirname(self.sqlite_path) or ".", exist_ok=True)
            self._init_sqlite()

    def get_connection(self):
        if self.is_postgres:
            import psycopg2
            from psycopg2.extras import RealDictCursor
            conn = psycopg2.connect(self.db_url)
            conn.autocommit = True
            return conn
        else:
            conn = sqlite3.connect(self.sqlite_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            return conn

    def _init_sqlite(self):
        conn = self.get_connection()
        cur = conn.cursor()
        
        # 1. Sensor Heartbeat & Health
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sensor_nodes (
                node_id TEXT PRIMARY KEY,
                hostname TEXT,
                ip TEXT,
                last_heartbeat REAL,
                status TEXT,
                containers_json TEXT,
                inetsim_status TEXT,
                db_status TEXT,
                db_size_mb REAL,
                model_version TEXT,
                metadata_json TEXT
            )
        """)

        # 2. Overview Stats Snapshot
        cur.execute("""
            CREATE TABLE IF NOT EXISTS overview_stats_snapshot (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_attacks_today INTEGER DEFAULT 0,
                active_attackers INTEGER DEFAULT 0,
                active_sessions INTEGER DEFAULT 0,
                threat_score_avg REAL DEFAULT 0.0,
                malware_captured INTEGER DEFAULT 0,
                countries_observed INTEGER DEFAULT 0,
                unique_profiles INTEGER DEFAULT 0,
                top_mitre_tactic TEXT DEFAULT 'Credential Access',
                high_risk_count INTEGER DEFAULT 0,
                sandbox_jobs INTEGER DEFAULT 0,
                active_honeypots INTEGER DEFAULT 5,
                updated_at REAL
            )
        """)

        # 3. Normalized Timeline Events
        cur.execute("""
            CREATE TABLE IF NOT EXISTS timeline_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                session_id TEXT,
                profile_id TEXT,
                source TEXT,
                event_type TEXT,
                severity INTEGER,
                command TEXT,
                username TEXT,
                password TEXT,
                src_ip TEXT,
                dst_port INTEGER,
                country TEXT,
                city TEXT,
                region TEXT,
                lat REAL,
                lon REAL,
                loc_available INTEGER,
                asn TEXT,
                org TEXT,
                metadata_json TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline_events(timestamp DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_timeline_src ON timeline_events(source)")

        # 4. Cowrie Sessions
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cowrie_sessions (
                session_id TEXT PRIMARY KEY,
                profile_id TEXT,
                src_ip TEXT,
                country TEXT,
                city TEXT,
                region TEXT,
                lat REAL,
                lon REAL,
                loc_available INTEGER,
                asn TEXT,
                org TEXT,
                username TEXT,
                password TEXT,
                ssh_client TEXT,
                persona TEXT,
                fingerprint_hash TEXT,
                command_count INTEGER DEFAULT 0,
                files_created INTEGER DEFAULT 0,
                files_downloaded INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 10.0,
                duration REAL DEFAULT 0.0,
                login_time TEXT,
                logout_time TEXT,
                commands_json TEXT,
                files_modified_json TEXT,
                auth_history_json TEXT,
                downloads_json TEXT,
                risk_evolution_json TEXT,
                tty_events_json TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cowrie_login ON cowrie_sessions(login_time DESC)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cowrie_profile ON cowrie_sessions(profile_id)")

        # 5. Suricata Alerts
        cur.execute("""
            CREATE TABLE IF NOT EXISTS suricata_alerts (
                alert_id TEXT PRIMARY KEY,
                signature TEXT,
                severity INTEGER,
                proto TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                packets INTEGER,
                bytes INTEGER,
                timestamp TEXT,
                event_type TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_suricata_ts ON suricata_alerts(timestamp DESC)")

        # 6. Heralding Credentials
        cur.execute("""
            CREATE TABLE IF NOT EXISTS heralding_credentials (
                cred_id TEXT PRIMARY KEY,
                username TEXT,
                password TEXT,
                protocol TEXT,
                attempts INTEGER DEFAULT 1,
                src_ip TEXT,
                country TEXT,
                timestamp TEXT,
                profile_id TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_heralding_ts ON heralding_credentials(timestamp DESC)")

        # 7. Dionaea Malware
        cur.execute("""
            CREATE TABLE IF NOT EXISTS dionaea_malware (
                malware_id TEXT PRIMARY KEY,
                sha256 TEXT,
                md5 TEXT,
                family TEXT,
                src_ip TEXT,
                vt_detections TEXT,
                download_url TEXT,
                country TEXT,
                timestamp TEXT,
                profile_id TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dionaea_ts ON dionaea_malware(timestamp DESC)")

        # 8. Conpot Events
        cur.execute("""
            CREATE TABLE IF NOT EXISTS conpot_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT,
                protocol TEXT,
                src_ip TEXT,
                dst_port INTEGER,
                event_type TEXT,
                value TEXT,
                country TEXT,
                profile_id TEXT
            )
        """)
        cur.execute("CREATE INDEX IF NOT EXISTS idx_conpot_ts ON conpot_events(timestamp DESC)")

        # 9. Sandbox Tasks
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_tasks (
                task_id TEXT PRIMARY KEY,
                timestamp TEXT,
                profile_id TEXT,
                filename TEXT,
                sha256 TEXT,
                md5 TEXT,
                verdict TEXT,
                risk_score REAL,
                duration REAL,
                processes_json TEXT,
                files_json TEXT,
                networks_json TEXT,
                dns_json TEXT
            )
        """)

        # 10. ML Profiles
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ml_profiles (
                profile_id TEXT PRIMARY KEY,
                prediction TEXT,
                confidence REAL,
                threat_score REAL,
                risk_level TEXT,
                behavior_score REAL,
                features_json TEXT,
                shap_importance_json TEXT,
                lime_explanation_json TEXT,
                updated_at REAL
            )
        """)

        # 11. Threat Graph
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_graph (
                graph_id INTEGER PRIMARY KEY CHECK (graph_id = 1),
                nodes_json TEXT,
                links_json TEXT,
                updated_at REAL
            )
        """)

        # 12. MITRE Mappings
        cur.execute("""
            CREATE TABLE IF NOT EXISTS mitre_mappings (
                technique_id TEXT PRIMARY KEY,
                technique_name TEXT,
                tactic TEXT,
                attackers_json TEXT,
                confidence TEXT,
                updated_at REAL
            )
        """)

        # 13. IOC Records
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ioc_records (
                ioc_id TEXT PRIMARY KEY,
                type TEXT,
                value TEXT,
                source TEXT,
                origin_profile TEXT,
                enrichment TEXT,
                details TEXT,
                timestamp REAL
            )
        """)

        # 14. Adaptive Memory
        cur.execute("""
            CREATE TABLE IF NOT EXISTS adaptive_memory (
                profile_id TEXT PRIMARY KEY,
                fingerprint_hash TEXT,
                persona TEXT,
                sessions INTEGER DEFAULT 0,
                first_seen TEXT,
                last_seen TEXT,
                files_created INTEGER DEFAULT 0,
                commands_executed INTEGER DEFAULT 0,
                files_downloaded INTEGER DEFAULT 0,
                vfs_state TEXT,
                behavior_score REAL DEFAULT 10.0,
                current_risk TEXT,
                updated_at REAL
            )
        """)

        # 15. Captured Artifacts
        cur.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                sha256 TEXT PRIMARY KEY,
                filename TEXT,
                size_bytes INTEGER,
                captured_at TEXT,
                vt_status TEXT,
                vt_data_json TEXT
            )
        """)

        # 16. Reports List
        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                report_id TEXT PRIMARY KEY,
                name TEXT,
                date TEXT,
                type TEXT,
                threats_detected INTEGER,
                content TEXT
            )
        """)

        conn.commit()
        conn.close()

    def _init_postgres(self):
        """Initializes tables in PostgreSQL if using Supabase/Render/Neon."""
        try:
            import psycopg2
            conn = psycopg2.connect(self.db_url)
            cur = conn.cursor()
            # Equivalent PostgreSQL DDL
            cur.execute("""
                CREATE TABLE IF NOT EXISTS sensor_nodes (
                    node_id TEXT PRIMARY KEY,
                    hostname TEXT,
                    ip TEXT,
                    last_heartbeat DOUBLE PRECISION,
                    status TEXT,
                    containers_json TEXT,
                    inetsim_status TEXT,
                    db_status TEXT,
                    db_size_mb DOUBLE PRECISION,
                    model_version TEXT,
                    metadata_json TEXT
                );
                CREATE TABLE IF NOT EXISTS overview_stats_snapshot (
                    id INTEGER PRIMARY KEY,
                    total_attacks_today INTEGER DEFAULT 0,
                    active_attackers INTEGER DEFAULT 0,
                    active_sessions INTEGER DEFAULT 0,
                    threat_score_avg DOUBLE PRECISION DEFAULT 0.0,
                    malware_captured INTEGER DEFAULT 0,
                    countries_observed INTEGER DEFAULT 0,
                    unique_profiles INTEGER DEFAULT 0,
                    top_mitre_tactic TEXT DEFAULT 'Credential Access',
                    high_risk_count INTEGER DEFAULT 0,
                    sandbox_jobs INTEGER DEFAULT 0,
                    active_honeypots INTEGER DEFAULT 5,
                    updated_at DOUBLE PRECISION
                );
                CREATE TABLE IF NOT EXISTS timeline_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    session_id TEXT,
                    profile_id TEXT,
                    source TEXT,
                    event_type TEXT,
                    severity INTEGER,
                    command TEXT,
                    username TEXT,
                    password TEXT,
                    src_ip TEXT,
                    dst_port INTEGER,
                    country TEXT,
                    city TEXT,
                    region TEXT,
                    lat DOUBLE PRECISION,
                    lon DOUBLE PRECISION,
                    loc_available INTEGER,
                    asn TEXT,
                    org TEXT,
                    metadata_json TEXT
                );
                CREATE TABLE IF NOT EXISTS cowrie_sessions (
                    session_id TEXT PRIMARY KEY,
                    profile_id TEXT,
                    src_ip TEXT,
                    country TEXT,
                    city TEXT,
                    region TEXT,
                    lat DOUBLE PRECISION,
                    lon DOUBLE PRECISION,
                    loc_available INTEGER,
                    asn TEXT,
                    org TEXT,
                    username TEXT,
                    password TEXT,
                    ssh_client TEXT,
                    persona TEXT,
                    fingerprint_hash TEXT,
                    command_count INTEGER DEFAULT 0,
                    files_created INTEGER DEFAULT 0,
                    files_downloaded INTEGER DEFAULT 0,
                    risk_score DOUBLE PRECISION DEFAULT 10.0,
                    duration DOUBLE PRECISION DEFAULT 0.0,
                    login_time TEXT,
                    logout_time TEXT,
                    commands_json TEXT,
                    files_modified_json TEXT,
                    auth_history_json TEXT,
                    downloads_json TEXT,
                    risk_evolution_json TEXT,
                    tty_events_json TEXT
                );
                CREATE TABLE IF NOT EXISTS suricata_alerts (
                    alert_id TEXT PRIMARY KEY,
                    signature TEXT,
                    severity INTEGER,
                    proto TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    dst_port INTEGER,
                    packets INTEGER,
                    bytes INTEGER,
                    timestamp TEXT,
                    event_type TEXT
                );
                CREATE TABLE IF NOT EXISTS heralding_credentials (
                    cred_id TEXT PRIMARY KEY,
                    username TEXT,
                    password TEXT,
                    protocol TEXT,
                    attempts INTEGER DEFAULT 1,
                    src_ip TEXT,
                    country TEXT,
                    timestamp TEXT,
                    profile_id TEXT
                );
                CREATE TABLE IF NOT EXISTS dionaea_malware (
                    malware_id TEXT PRIMARY KEY,
                    sha256 TEXT,
                    md5 TEXT,
                    family TEXT,
                    src_ip TEXT,
                    vt_detections TEXT,
                    download_url TEXT,
                    country TEXT,
                    timestamp TEXT,
                    profile_id TEXT
                );
                CREATE TABLE IF NOT EXISTS conpot_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_port INTEGER,
                    event_type TEXT,
                    value TEXT,
                    country TEXT,
                    profile_id TEXT
                );
                CREATE TABLE IF NOT EXISTS sandbox_tasks (
                    task_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    profile_id TEXT,
                    filename TEXT,
                    sha256 TEXT,
                    md5 TEXT,
                    verdict TEXT,
                    risk_score DOUBLE PRECISION,
                    duration DOUBLE PRECISION,
                    processes_json TEXT,
                    files_json TEXT,
                    networks_json TEXT,
                    dns_json TEXT
                );
                CREATE TABLE IF NOT EXISTS ml_profiles (
                    profile_id TEXT PRIMARY KEY,
                    prediction TEXT,
                    confidence DOUBLE PRECISION,
                    threat_score DOUBLE PRECISION,
                    risk_level TEXT,
                    behavior_score DOUBLE PRECISION,
                    features_json TEXT,
                    shap_importance_json TEXT,
                    lime_explanation_json TEXT,
                    updated_at DOUBLE PRECISION
                );
                CREATE TABLE IF NOT EXISTS threat_graph (
                    graph_id INTEGER PRIMARY KEY,
                    nodes_json TEXT,
                    links_json TEXT,
                    updated_at DOUBLE PRECISION
                );
                CREATE TABLE IF NOT EXISTS mitre_mappings (
                    technique_id TEXT PRIMARY KEY,
                    technique_name TEXT,
                    tactic TEXT,
                    attackers_json TEXT,
                    confidence TEXT,
                    updated_at DOUBLE PRECISION
                );
                CREATE TABLE IF NOT EXISTS ioc_records (
                    ioc_id TEXT PRIMARY KEY,
                    type TEXT,
                    value TEXT,
                    source TEXT,
                    origin_profile TEXT,
                    enrichment TEXT,
                    details TEXT,
                    timestamp DOUBLE PRECISION
                );
                CREATE TABLE IF NOT EXISTS adaptive_memory (
                    profile_id TEXT PRIMARY KEY,
                    fingerprint_hash TEXT,
                    persona TEXT,
                    sessions INTEGER DEFAULT 0,
                    first_seen TEXT,
                    last_seen TEXT,
                    files_created INTEGER DEFAULT 0,
                    commands_executed INTEGER DEFAULT 0,
                    files_downloaded INTEGER DEFAULT 0,
                    vfs_state TEXT,
                    behavior_score DOUBLE PRECISION DEFAULT 10.0,
                    current_risk TEXT,
                    updated_at DOUBLE PRECISION
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    sha256 TEXT PRIMARY KEY,
                    filename TEXT,
                    size_bytes INTEGER,
                    captured_at TEXT,
                    vt_status TEXT,
                    vt_data_json TEXT
                );
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    name TEXT,
                    date TEXT,
                    type TEXT,
                    threats_detected INTEGER,
                    content TEXT
                );
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"[CLOUD DB WARN] PostgreSQL initialization failed ({e}), falling back to SQLite.")
            self.is_postgres = False
            self.sqlite_path = os.path.abspath("./hellguardian_cloud.db")
            self._init_sqlite()

db = CloudDatabase()
