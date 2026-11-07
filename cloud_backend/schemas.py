from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

class HeartbeatPayload(BaseModel):
    node_id: str = "local-tpot-node"
    hostname: Optional[str] = "tpot-vm"
    ip: Optional[str] = "127.0.0.1"
    status: str = "Online"
    containers: Dict[str, str] = Field(default_factory=dict)
    inetsim_status: str = "Offline"
    db_status: str = "Online"
    db_size_mb: float = 0.0
    model_version: str = "2.0.3"
    timestamp: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class IngestPayload(BaseModel):
    node_id: str = "local-tpot-node"
    overview_stats: Optional[Dict[str, Any]] = None
    timeline_events: List[Dict[str, Any]] = Field(default_factory=list)
    cowrie_sessions: List[Dict[str, Any]] = Field(default_factory=list)
    suricata_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    heralding_credentials: List[Dict[str, Any]] = Field(default_factory=list)
    dionaea_malware: List[Dict[str, Any]] = Field(default_factory=list)
    conpot_events: List[Dict[str, Any]] = Field(default_factory=list)
    sandbox_tasks: List[Dict[str, Any]] = Field(default_factory=list)
    ml_profiles: List[Dict[str, Any]] = Field(default_factory=list)
    threat_graph: Optional[Dict[str, Any]] = None
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    adaptive_memory: List[Dict[str, Any]] = Field(default_factory=list)
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    reports: List[Dict[str, Any]] = Field(default_factory=list)

class IngestResponse(BaseModel):
    status: str
    message: str
    counts: Dict[str, int]
    timestamp: float
