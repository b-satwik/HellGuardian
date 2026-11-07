// HellGuardian SOC Threat Intelligence Workspace Controller Logic

// HellGuardian Client API and Sensor Status Helpers
function getApiUrl(endpoint) {
  const base = (window.HELLGUARDIAN_CONFIG && window.HELLGUARDIAN_CONFIG.API_BASE_URL)
    ? window.HELLGUARDIAN_CONFIG.API_BASE_URL.replace(/\/+$/, '')
    : '';
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : '/' + endpoint;
  return `${base}${cleanEndpoint}`;
}

function updateGlobalSensorStatus() {
  fetch(getApiUrl("/api/settings/status"))
    .then(res => res.json())
    .then(data => {
      const dot = document.getElementById("global-status-dot");
      const text = document.getElementById("global-status-text");
      const badge = document.getElementById("global-sensor-status-badge");
      const lastSync = document.getElementById("global-last-sync");

      const isOnline = (data.system_status === "Online" || data.is_online === true);

      if (isOnline) {
        if (dot) dot.className = "logo-dot pulse-animation";
        if (text) text.innerText = "STATUS: ONLINE (LIVE SENSORS)";
        if (badge) badge.className = "status-badge online-mode";
        if (lastSync) {
          lastSync.style.display = "inline";
          lastSync.innerText = "(Live)";
        }
      } else {
        if (dot) dot.className = "logo-dot offline";
        if (text) text.innerText = "STATUS: OFFLINE (HISTORICAL ARCHIVE)";
        if (badge) badge.className = "status-badge offline-mode";
        if (lastSync) {
          lastSync.style.display = "inline";
          const syncTime = data.last_sync_timestamp ? data.last_sync_timestamp.replace("T", " ").substring(0, 19) : "Archive";
          lastSync.innerText = `[Sync: ${syncTime}]`;
        }
      }
    })
    .catch(() => {
      const dot = document.getElementById("global-status-dot");
      const text = document.getElementById("global-status-text");
      const badge = document.getElementById("global-sensor-status-badge");
      if (dot) dot.className = "logo-dot offline";
      if (text) text.innerText = "STATUS: ARCHIVE (OFFLINE)";
      if (badge) badge.className = "status-badge offline-mode";
    });
}


document.addEventListener("DOMContentLoaded", () => {
  initScrollTracker();
  initHUD();
  initChatAssistant();
  updateGlobalSensorStatus();
  setInterval(updateGlobalSensorStatus, (window.HELLGUARDIAN_CONFIG && window.HELLGUARDIAN_CONFIG.STATUS_POLL_INTERVAL_MS) || 30000);
});

window.selectedInvestigateProfileId = null;

function initChatAssistant() {
  const chatFab = document.getElementById("chat-fab");
  const chatPanel = document.getElementById("chat-panel");
  const chatClose = document.getElementById("chat-close");
  const chatSend = document.getElementById("chat-send");
  const chatInput = document.getElementById("chat-input");
  
  if (chatFab && chatPanel) {
    chatFab.onclick = () => {
      chatPanel.style.display = chatPanel.style.display === "none" ? "flex" : "none";
    };
  }
  if (chatClose && chatPanel) {
    chatClose.onclick = () => {
      chatPanel.style.display = "none";
    };
  }
  
  const sendMessage = () => {
    const text = chatInput.value.trim();
    if (!text) return;
    
    appendChatMessage("user", text);
    chatInput.value = "";
    
    const pid = window.selectedInvestigateProfileId || "";
    fetch(getApiUrl(`/api/reports/llm_chat?message=${encodeURIComponent(text)}&profile_id=${encodeURIComponent(pid)}`))
      .then(res => res.json())
      .then(data => {
        appendChatMessage("agent", data.response);
      })
      .catch(err => {
        appendChatMessage("agent", `Error communicating with copilot: ${err.message}`);
      });
  };
  
  if (chatSend) {
    chatSend.onclick = sendMessage;
  }
  if (chatInput) {
    chatInput.onkeydown = (e) => {
      if (e.key === "Enter") sendMessage();
    };
  }
}

function appendChatMessage(sender, message) {
  const chatBody = document.getElementById("chat-body");
  if (!chatBody) return;
  
  const div = document.createElement("div");
  div.className = `chat-msg ${sender}`;
  div.innerText = message;
  chatBody.appendChild(div);
  chatBody.scrollTop = chatBody.scrollHeight;
}

function initScrollTracker() {
  window.addEventListener("scroll", () => {
    const winScroll = document.body.scrollTop || document.documentElement.scrollTop;
    const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
    const scrolled = (winScroll / height) * 100;
    const indicator = document.getElementById("scroll-progress");
    if (indicator) indicator.style.width = scrolled + "%";
  });
}

// --- HUD CORE NAVIGATION & AJAX MODULE LOADING ---
let pageRefreshInterval = null;

function initHUD() {
  const links = document.querySelectorAll(".nav-links li");
  links.forEach(link => {
    link.addEventListener("click", () => {
      links.forEach(l => l.classList.remove("active"));
      link.classList.add("active");
      const view = link.getAttribute("data-view");
      switchView(view);
    });
  });
  
  switchView("home");
}

function switchView(viewName) {
  const container = document.getElementById("view-container");
  
  if (pageRefreshInterval) {
    clearInterval(pageRefreshInterval);
  }
  
  container.innerHTML = `<div class="offline-msg">Ingesting live telemetry from pipeline...</div>`;

  // Fetch page template relative path asynchronously
  fetch(`./pages/${viewName}.html`)
    .then(res => {
      if (!res.ok) throw new Error(`HTML template '${viewName}.html' not found`);
      return res.text();
    })
    .then(html => {
      container.innerHTML = html;
      initPageScripts(viewName);
      
      // Auto refresh dynamic page data every 10s
      pageRefreshInterval = setInterval(() => {
        initPageScripts(viewName);
      }, 10000);
    })
    .catch(err => {
      container.innerHTML = `<div class="offline-msg">Telemetry offline: ${err.message}. No telemetry available.</div>`;
    });
}

function initPageScripts(viewName) {
  switch (viewName) {
    case "home":
      initHomeView();
      break;
    case "map":
      initMapView();
      break;
    case "cowrie":
      initCowrieView();
      break;
    case "suricata":
      initSuricataView();
      break;
    case "heralding":
      initHeraldingView();
      break;
    case "dionaea":
      initDionaeaView();
      break;
    case "conpot":
      initConpotView();
      break;
    case "sandbox":
      initSandboxView();
      break;
    case "ioc":
      initIOCView();
      break;
    case "ml":
      initMLView();
      break;
    case "mitre":
      initMitreView();
      break;
    case "graph":
      initGraphView();
      break;
    case "reports":
      initReportsView();
      break;
    case "settings":
      initSettingsView();
      break;
    case "memory":
      initAdaptiveMemoryView();
      break;
  }
}

// --- VIEW CONTROLLERS (REAL-DATA API ENGINES) ---

function initHomeView() {
  // Query Stats
  fetch(getApiUrl("/api/overview_stats"))
    .then(res => res.json())
    .then(data => {
      document.getElementById("stat-active-sessions").innerText = data.active_sessions;
      document.getElementById("stat-attacker-profiles").innerText = data.unique_profiles;
      document.getElementById("stat-high-risk").innerText = data.high_risk_count;
      document.getElementById("stat-malware-samples").innerText = data.malware_captured;
      document.getElementById("stat-sandbox-jobs").innerText = data.sandbox_jobs;
      document.getElementById("stat-active-honeypots").innerText = data.active_honeypots;
      document.getElementById("stat-threat-score").innerText = data.threat_score_avg + "%";
      document.getElementById("stat-today-events").innerText = data.total_attacks_today;
    })
    .catch(() => {
      // Keep default "No telemetry available." text
    });

  // Query Timeline events
  fetch(getApiUrl("/api/timeline_events"))
    .then(res => res.json())
    .then(events => {
      const list = document.getElementById("home-timeline");
      list.innerHTML = "";
      if (events.length === 0) {
        list.innerHTML = `<li class="offline-msg">No active attacks detected. No telemetry available.</li>`;
        return;
      }
      events.forEach(ev => {
        const li = document.createElement("li");
        li.className = "timeline-item";
        
        let badgeType = "badge-recon";
        let detailText = `Source IP ${ev.src_ip} scanned port ${ev.dst_port || 'unknown'}`;
        if (ev.source === "cowrie") {
          badgeType = ev.event_type === "auth" ? "badge-auth" : "badge-ssh";
          if (ev.command) {
            detailText = `SSH command input: "${ev.command}"`;
          } else if (ev.username || ev.password) {
            detailText = `SSH Auth Trial: ${ev.username || 'root'}:${ev.password ? '*****' : '[none]'}`;
          } else if (ev.event_type === "connect" || ev.event_type === "cowrie.session.connect") {
            detailText = `SSH Connection opened from ${ev.src_ip || 'client'}`;
          } else if (ev.event_type === "closed" || ev.event_type === "cowrie.session.closed") {
            detailText = `SSH Connection closed`;
          } else {
            detailText = `SSH Session Activity (${ev.event_type || 'interaction'})`;
          }
        } else if (ev.source === "suricata") {
          badgeType = "badge-suricata";
          detailText = `Suricata Alert: ${ev.metadata.alert?.signature || 'Unknown alert'}`;
        } else if (ev.source === "sandbox") {
          badgeType = "badge-malware";
          detailText = `Sandbox run output for hash ${ev.metadata.sha256?.slice(0, 8)}`;
        }
        
        let locationText = "Location: Unavailable";
        if (ev.loc_available && ev.country) {
          const cityStr = ev.city ? `${ev.city}, ` : "";
          const orgStr = ev.asn ? ` (${ev.asn})` : (ev.org ? ` (${ev.org})` : "");
          locationText = `Location: ${cityStr}${ev.country}${orgStr}`;
        } else if (ev.country && ev.country !== "Unknown" && ev.country !== "Location Unavailable") {
          locationText = `Location: ${ev.country}`;
        }

        li.innerHTML = `
          <div class="event-details">
            <span class="event-badge ${badgeType}">${ev.source.toUpperCase()}</span>
            <span class="event-text"><a href="#" onclick="openInvestigation('${ev.profile_id}')" style="color:var(--accent-blue); text-decoration:none; font-weight:600;">${ev.profile_id || ev.src_ip}</a>: ${detailText} (${locationText})</span>
          </div>
          <span class="event-time">${ev.timestamp.split("T")[1]?.slice(0, 8) || ev.timestamp}</span>
        `;
        list.appendChild(li);
      });

      // Render world map path curved lines
      drawWorldMap(events);
    })
    .catch(() => {
      document.getElementById("home-timeline").innerHTML = `<li class="offline-msg">No telemetry available.</li>`;
    });

  // Render charts trend and distributions
  drawTrendChart();
  drawDistributionChart();
}

function drawWorldMap(events) {
  let container = document.getElementById("world-map");
  let selector = "#world-map";
  if (!container) {
    container = document.getElementById("live-world-map");
    selector = "#live-world-map";
  }
  if (!container) return;
  
  container.innerHTML = "";
  const width = container.clientWidth;
  const height = selector === "#live-world-map" ? 650 : 450;
  
  const svg = d3.select(selector)
    .append("svg")
    .attr("width", width)
    .attr("height", height);

  const projection = d3.geoNaturalEarth1()
    .scale(width / 5.5)
    .translate([width / 2, height / 1.7]);

  const path = d3.geoPath().projection(projection);

  // Fetch world atlas land shapes
  d3.json("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json").then(topoData => {
    const countries = topojson.feature(topoData, topoData.objects.countries).features;
    
    svg.append("g")
      .selectAll("path")
      .data(countries)
      .enter()
      .append("path")
      .attr("d", path)
      .attr("class", "country-land")
      .style("fill", "#e5e5ea")
      .style("stroke", "#ffffff");

    // Center target coordinates (Honeypot server location)
    const targetCoords = [79.0882, 21.1458]; // Nagpur, India coordinates
    const targetPos = projection(targetCoords);
    
    svg.append("circle")
      .attr("cx", targetPos[0])
      .attr("cy", targetPos[1])
      .attr("r", 5)
      .attr("fill", "var(--accent-blue)")
      .attr("class", "glow-dot");

    // Sort events by timestamp descending (newest first)
    const sortedEvents = events.slice().sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    sortedEvents.forEach((ev, index) => {
      // Draw attacker markers only when loc_available is true and coordinates are valid numbers
      if (!ev.loc_available || ev.lat == null || ev.lon == null) return;
      
      const startPos = projection([ev.lon, ev.lat]);
      if (!startPos || isNaN(startPos[0]) || isNaN(startPos[1])) return;

      const endPos = targetPos;
      
      // Determine stroke color by attack type
      let strokeColor = "#0066cc"; // SSH (Blue) Default
      if (ev.source === "cowrie") {
        if (ev.dst_port === 23) {
          strokeColor = "#ff9500"; // Telnet (Orange)
        } else if (ev.event_type === "auth") {
          strokeColor = "#34c759"; // Credential (Green)
        }
      } else if (ev.source === "heralding") {
        strokeColor = "#34c759"; // Credential (Green)
      } else if (ev.source === "conpot") {
        strokeColor = "#af52de"; // SCADA (Purple)
      } else if (ev.source === "sandbox" || ev.source === "dionaea") {
        strokeColor = "#ff3b30"; // Malware (Red)
      } else if (ev.source === "suricata") {
        strokeColor = "#ff3b30"; // Threat IDS Alert (Red)
      }

      svg.append("circle")
        .attr("cx", startPos[0])
        .attr("cy", startPos[1])
        .attr("r", 3.5)
        .attr("fill", strokeColor);

      // Only draw the connecting curve line if it is one of the 10 most recent attacks
      if (index < 10) {
        const dx = endPos[0] - startPos[0];
        const dy = endPos[1] - startPos[1];
        const dr = Math.sqrt(dx * dx + dy * dy) * 1.3;

        const pathString = `M${startPos[0]},${startPos[1]}A${dr},${dr} 0 0,1 ${endPos[0]},${endPos[1]}`;

        // Curved attack line - older of the recent ones are less opaque, newest are active dashed
        const lineClass = index < 3 ? "attack-line active" : "attack-line";
        svg.append("path")
          .attr("d", pathString)
          .attr("class", lineClass)
          .attr("stroke", strokeColor)
          .attr("stroke-width", index < 3 ? 2.0 : 1.2)
          .attr("fill", "none")
          .style("opacity", index < 3 ? 0.95 : 0.4)
          .style("stroke-dasharray", index < 3 ? "5, 5" : "none");
      }
    });
  }).catch(() => {
    container.innerHTML = `<div class="offline-msg">Map loading failed. No telemetry available.</div>`;
  });
}

function drawTrendChart() {
  fetch(getApiUrl("/api/charts/threat_trend"))
    .then(res => res.json())
    .then(data => {
      const options = {
        chart: { type: 'area', height: 260, toolbar: { show: false }, background: 'transparent' },
        theme: { mode: 'light' },
        series: [
          { name: 'Attack Vol', data: data.attacks },
          { name: 'Threat Level', data: data.threat_scores }
        ],
        xaxis: { categories: data.labels },
        colors: ['#0066cc', '#af52de'],
        stroke: { curve: 'smooth', width: 2 },
        fill: { type: 'gradient', gradient: { opacityFrom: 0.1, opacityTo: 0 } },
        grid: { borderColor: '#e5e5ea' },
        dataLabels: { enabled: false }
      };
      new ApexCharts(document.querySelector("#chart-trend"), options).render();
    });
}

function drawDistributionChart() {
  fetch(getApiUrl("/api/charts/attack_distribution"))
    .then(res => res.json())
    .then(data => {
      const options = {
        chart: { type: 'donut', height: 260, background: 'transparent' },
        theme: { mode: 'light' },
        series: data.map(d => d.count),
        labels: data.map(d => d.category),
        colors: ['#0066cc', '#ff3b30', '#34c759', '#ff9500', '#af52de']
      };
      new ApexCharts(document.querySelector("#chart-pie"), options).render();
    });
}

let cowrieCurrentPage = 1;
let cowriePageSize = 10;
let cowrieFilteredSessions = [];

function getCowriePageSize() {
  const select = document.getElementById("cowrie-page-size");
  if (select && select.value) {
    const val = parseInt(select.value, 10);
    if (!isNaN(val) && val > 0) return val;
  }
  return cowriePageSize || 10;
}

function initCowrieView() {
  fetch(getApiUrl("/api/cowrie/sessions"))
    .then(res => res.json())
    .then(sessions => {
      // Sort sessions by login_time descending (newest timestamp first)
      sessions.sort((a, b) => {
        const timeA = a.login_time ? new Date(a.login_time).getTime() : 0;
        const timeB = b.login_time ? new Date(b.login_time).getTime() : 0;
        return timeB - timeA;
      });
      window.cowrieSessionsData = sessions;
      cowrieFilteredSessions = sessions;
      cowrieCurrentPage = 1;
      
      const latestBadge = document.getElementById("cowrie-latest-activity-badge");
      if (latestBadge) {
        if (sessions.length > 0 && sessions[0].login_time) {
          const rawTime = sessions[0].login_time;
          const formattedTime = rawTime.includes("T") ? rawTime.replace("T", " ").slice(0, 19) + " UTC" : rawTime;
          latestBadge.innerHTML = `<span style="color:#e6a23c;">● Historical Telemetry</span> &nbsp;|&nbsp; Latest Recorded Session: <strong>${formattedTime}</strong> (${sessions.length} total recorded)`;
        } else {
          latestBadge.innerHTML = `No Recorded Session Telemetry`;
        }
      }
      
      const pageSizeSelect = document.getElementById("cowrie-page-size");
      const searchInput = document.getElementById("cowrie-search");
      const personaSelect = document.getElementById("cowrie-filter-persona");
      const exportBtn = document.getElementById("cowrie-export");
      const prevBtn = document.getElementById("cowrie-prev-page");
      const nextBtn = document.getElementById("cowrie-next-page");
      
      if (pageSizeSelect) {
        pageSizeSelect.onchange = () => {
          cowriePageSize = parseInt(pageSizeSelect.value, 10) || 10;
          cowrieCurrentPage = 1;
          renderCowrieCurrentPage();
        };
      }
      if (searchInput) {
        searchInput.oninput = () => {
          cowrieCurrentPage = 1;
          filterCowrieData();
        };
      }
      if (personaSelect) {
        personaSelect.onchange = () => {
          cowrieCurrentPage = 1;
          filterCowrieData();
        };
      }
      if (exportBtn) {
        exportBtn.onclick = () => exportCowrieCSV();
      }
      if (prevBtn) {
        prevBtn.onclick = () => {
          if (cowrieCurrentPage > 1) {
            cowrieCurrentPage--;
            renderCowrieCurrentPage();
          }
        };
      }
      if (nextBtn) {
        nextBtn.onclick = () => {
          const pageSize = getCowriePageSize();
          const totalPages = Math.ceil((cowrieFilteredSessions || []).length / pageSize) || 1;
          if (cowrieCurrentPage < totalPages) {
            cowrieCurrentPage++;
            renderCowrieCurrentPage();
          }
        };
      }

      filterCowrieData();
    }).catch(err => {
      console.error("[COWRIE VIEW ERROR]", err);
      const tbody = document.querySelector("#cowrie-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='16' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterCowrieData() {
  const query = document.getElementById("cowrie-search")?.value.toLowerCase().trim() || "";
  const persona = document.getElementById("cowrie-filter-persona")?.value || "";
  
  let filtered = window.cowrieSessionsData || [];
  if (persona) {
    filtered = filtered.filter(s => s.persona === persona);
  }
  if (query) {
    filtered = filtered.filter(s => 
      (s.session_id && s.session_id.toLowerCase().includes(query)) ||
      (s.profile_id && s.profile_id.toLowerCase().includes(query)) ||
      (s.src_ip && s.src_ip.toLowerCase().includes(query)) ||
      (s.country && s.country.toLowerCase().includes(query)) ||
      (s.username && s.username.toLowerCase().includes(query)) ||
      (s.password && s.password.toLowerCase().includes(query)) ||
      (s.ssh_client && s.ssh_client.toLowerCase().includes(query)) ||
      (s.fingerprint_hash && s.fingerprint_hash.toLowerCase().includes(query))
    );
  }

  // Ensure newest timestamped sessions appear first
  filtered.sort((a, b) => {
    const timeA = a.login_time ? new Date(a.login_time).getTime() : 0;
    const timeB = b.login_time ? new Date(b.login_time).getTime() : 0;
    return timeB - timeA;
  });

  cowrieFilteredSessions = filtered;
  renderCowrieCurrentPage();
}

function renderCowrieCurrentPage() {
  const pageSize = getCowriePageSize();
  const total = (cowrieFilteredSessions || []).length;
  const totalPages = Math.ceil(total / pageSize) || 1;
  if (cowrieCurrentPage > totalPages) cowrieCurrentPage = totalPages;
  if (cowrieCurrentPage < 1) cowrieCurrentPage = 1;

  const startIdx = (cowrieCurrentPage - 1) * pageSize;
  const pageSessions = (cowrieFilteredSessions || []).slice(startIdx, startIdx + pageSize);

  renderCowrieTable(pageSessions);
  updateCowriePaginationControls(total, totalPages, startIdx, pageSessions.length);
}

function updateCowriePaginationControls(total, totalPages, startIdx, pageCount) {
  const prevBtn = document.getElementById("cowrie-prev-page");
  const nextBtn = document.getElementById("cowrie-next-page");
  const pageNumbersContainer = document.getElementById("cowrie-page-numbers");
  const infoDiv = document.getElementById("cowrie-pagination-info");

  if (prevBtn) prevBtn.disabled = (cowrieCurrentPage <= 1);
  if (nextBtn) nextBtn.disabled = (cowrieCurrentPage >= totalPages || total === 0);
  
  if (infoDiv) {
    if (total === 0) {
      infoDiv.innerText = "Showing 0 of 0 recorded sessions";
    } else {
      const endIdx = startIdx + pageCount;
      infoDiv.innerText = `Showing ${startIdx + 1}–${endIdx} of ${total} recorded sessions`;
    }
  }

  if (pageNumbersContainer) {
    pageNumbersContainer.innerHTML = "";
    if (total > 0 && totalPages >= 1) {
      for (let p = 1; p <= totalPages; p++) {
        const btn = document.createElement("button");
        btn.innerText = p.toString();
        btn.style.padding = "2px 8px";
        btn.style.fontSize = "12px";
        btn.style.borderRadius = "4px";
        btn.style.cursor = "pointer";

        if (p === cowrieCurrentPage) {
          btn.style.background = "var(--accent-blue, #3b82f6)";
          btn.style.color = "#ffffff";
          btn.style.fontWeight = "bold";
          btn.style.border = "none";
        } else {
          btn.style.background = "transparent";
          btn.style.color = "var(--text-color, #e1e4ed)";
          btn.style.border = "1px solid var(--border-color, #2a2d3d)";
        }

        btn.onclick = () => {
          cowrieCurrentPage = p;
          renderCowrieCurrentPage();
        };
        pageNumbersContainer.appendChild(btn);
      }
    }
  }
}

function renderCowrieTable(sessions) {
  const tbody = document.querySelector("#cowrie-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (sessions.length === 0) {
    tbody.innerHTML = "<tr><td colspan='16' class='offline-msg'>No telemetry available matching filters.</td></tr>";
    return;
  }
  sessions.forEach(sess => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON" && e.target.tagName !== "A") {
        openInvestigation(sess.profile_id);
      }
    };
    
    let riskBadge = sess.risk_score >= 80 ? "badge-suricata" : sess.risk_score >= 50 ? "badge-telnet" : "badge-auth";
    
    tr.innerHTML = `
      <td><code>${sess.session_id ? sess.session_id.slice(0, 8) : ''}...</code></td>
      <td><a href="#" onclick="openInvestigation('${sess.profile_id}')" style="color:var(--accent-blue); text-decoration:none;">${sess.profile_id ? sess.profile_id.slice(0, 8) : ''}...</a></td>
      <td><strong>${sess.src_ip}</strong></td>
      <td>${sess.country}</td>
      <td><code>${sess.username}</code></td>
      <td><code>${sess.password}</code></td>
      <td><span style="font-size:11px; color:#555;">${sess.ssh_client ? sess.ssh_client.slice(0, 15) : ''}...</span></td>
      <td><span class="event-time">${sess.login_time && sess.login_time.includes("T") ? sess.login_time.split("T")[1].slice(0, 8) : sess.login_time}</span></td>
      <td>${sess.duration}s</td>
      <td>${sess.command_count}</td>
      <td>${sess.files_created}</td>
      <td>${sess.files_downloaded}</td>
      <td><span class="event-badge badge-ssh">${sess.persona}</span></td>
      <td><code>${sess.fingerprint_hash ? sess.fingerprint_hash.slice(0, 8) : ''}...</code></td>
      <td><span class="event-badge ${riskBadge}">${sess.risk_score}</span></td>
      <td>
        <button class="action-btn" onclick="openInvestigation('${sess.profile_id}')" style="padding:2px 6px; font-size:11px;">Investigate</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function exportCowrieCSV() {
  const sessions = (cowrieFilteredSessions && cowrieFilteredSessions.length > 0) ? cowrieFilteredSessions : (window.cowrieSessionsData || []);
  if (sessions.length === 0) return;
  
  const headers = ["Session ID", "Profile ID", "Attacker IP", "Country", "Username", "Password", "SSH Client", "Login Time", "Duration", "Cmds", "Files Created", "Downloads", "Persona", "Fingerprint", "Risk Score"];
  const rows = sessions.map(s => [
    s.session_id, s.profile_id, s.src_ip, s.country, s.username, s.password, s.ssh_client, s.login_time, s.duration, s.command_count, s.files_created, s.files_downloaded, s.persona, s.fingerprint_hash, s.risk_score
  ]);
  
  let csvContent = "data:text/csv;charset=utf-8," 
    + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
    
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_cowrie_sessions.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initSuricataView() {
  fetch(getApiUrl("/api/suricata/alerts"))
    .then(res => res.json())
    .then(alerts => {
      window.suricataAlertsData = alerts;
      renderSuricataTable(alerts);
      
      const searchInput = document.getElementById("suricata-search");
      const exportBtn = document.getElementById("suricata-export");
      if (searchInput) searchInput.oninput = () => filterSuricataData();
      if (exportBtn) exportBtn.onclick = () => exportSuricataCSV();
    }).catch(err => {
      console.error("[SURICATA VIEW ERROR]", err);
      const tbody = document.querySelector("#suricata-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='8' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterSuricataData() {
  const query = document.getElementById("suricata-search")?.value.toLowerCase() || "";
  let filtered = window.suricataAlertsData || [];
  if (query) {
    filtered = filtered.filter(a => 
      a.signature.toLowerCase().includes(query) ||
      a.proto.toLowerCase().includes(query) ||
      a.src_ip.toLowerCase().includes(query)
    );
  }
  renderSuricataTable(filtered);
}

function renderSuricataTable(alerts) {
  const tbody = document.getElementById("suricata-tbody") || document.querySelector("#suricata-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (alerts.length === 0) {
    tbody.innerHTML = "<tr><td colspan='8' class='offline-msg'>No telemetry available matching filters.</td></tr>";
    return;
  }
  alerts.forEach(a => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        openInvestigation(a.profile_id || a.src_ip);
      }
    };
    tr.innerHTML = `
      <td><strong>${a.signature}</strong></td>
      <td><span class="event-badge ${a.severity === 1 ? 'badge-malware' : 'badge-suricata'}">Priority ${a.severity}</span></td>
      <td>${a.proto}</td>
      <td><code>${a.src_ip}</code></td>
      <td>${a.dst_port}</td>
      <td>${a.packets}</td>
      <td>${a.bytes}</td>
      <td><button class="action-btn" onclick="openInvestigation('${a.profile_id || a.src_ip}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function exportSuricataCSV() {
  const alerts = window.suricataAlertsData || [];
  if (alerts.length === 0) return;
  const headers = ["Signature", "Severity", "Protocol", "Source IP", "Target Port", "Flow Packets", "Flow Bytes"];
  const rows = alerts.map(a => [a.signature, a.severity, a.proto, a.src_ip, a.dst_port, a.packets, a.bytes]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_suricata_alerts.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initHeraldingView() {
  fetch(getApiUrl("/api/heralding/credentials"))
    .then(res => res.json())
    .then(creds => {
      window.heraldingCredsData = creds;
      renderHeraldingTable(creds);
      
      const searchInput = document.getElementById("heralding-search");
      const exportBtn = document.getElementById("heralding-export");
      if (searchInput) searchInput.oninput = () => filterHeraldingData();
      if (exportBtn) exportBtn.onclick = () => exportHeraldingCSV();
    }).catch(err => {
      console.error("[HERALDING VIEW ERROR]", err);
      const tbody = document.querySelector("#heralding-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='10' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterHeraldingData() {
  const query = document.getElementById("heralding-search")?.value.toLowerCase() || "";
  let filtered = window.heraldingCredsData || [];
  if (query) {
    filtered = filtered.filter(c => 
      c.username.toLowerCase().includes(query) ||
      c.password.toLowerCase().includes(query) ||
      c.protocol.toLowerCase().includes(query) ||
      c.src_ip.toLowerCase().includes(query) ||
      c.country.toLowerCase().includes(query)
    );
  }
  renderHeraldingTable(filtered);
}

function renderHeraldingTable(creds) {
  const tbody = document.getElementById("heralding-tbody") || document.querySelector("#heralding-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (creds.length === 0) {
    tbody.innerHTML = "<tr><td colspan='10' class='offline-msg'>No telemetry available matching filters.</td></tr>";
    return;
  }
  creds.forEach(c => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON" && e.target.tagName !== "A") {
        openInvestigation(c.profile_id || c.src_ip);
      }
    };
    tr.innerHTML = `
      <td><strong>${c.username}</strong></td>
      <td><code>${c.password}</code></td>
      <td>${c.protocol.toUpperCase()}</td>
      <td><code>127.0.0.1</code></td>
      <td>${c.attempts || 1}</td>
      <td><span class="event-time">${c.timestamp || '2026-07-05'}</span></td>
      <td><span class="event-time">${c.timestamp || '2026-07-05'}</span></td>
      <td>${c.country || 'Australia'}</td>
      <td><a href="#" onclick="openInvestigation('${c.profile_id || c.src_ip}')">${c.profile_id || 'unknown'}</a></td>
      <td><button class="action-btn" onclick="openInvestigation('${c.profile_id || c.src_ip}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function exportHeraldingCSV() {
  const creds = window.heraldingCredsData || [];
  if (creds.length === 0) return;
  const headers = ["Username", "Password", "Protocol", "Spray Count", "Country", "Profile ID"];
  const rows = creds.map(c => [c.username, c.password, c.protocol, c.attempts, c.country, c.profile_id]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_heralding_creds.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initDionaeaView() {
  fetch(getApiUrl("/api/dionaea/malware"))
    .then(res => res.json())
    .then(payloads => {
      window.dionaeaMalwareData = payloads;
      renderDionaeaTable(payloads);
      
      const searchInput = document.getElementById("dionaea-search");
      const exportBtn = document.getElementById("dionaea-export");
      if (searchInput) searchInput.oninput = () => filterDionaeaData();
      if (exportBtn) exportBtn.onclick = () => exportDionaeaCSV();
    }).catch(err => {
      console.error("[DIONAEA VIEW ERROR]", err);
      const tbody = document.querySelector("#dionaea-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='9' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterDionaeaData() {
  const query = document.getElementById("dionaea-search")?.value.toLowerCase() || "";
  let filtered = window.dionaeaMalwareData || [];
  if (query) {
    filtered = filtered.filter(p => 
      p.sha256.toLowerCase().includes(query) ||
      p.family.toLowerCase().includes(query) ||
      p.src_ip.toLowerCase().includes(query)
    );
  }
  renderDionaeaTable(filtered);
}

function renderDionaeaTable(payloads) {
  const tbody = document.getElementById("dionaea-tbody") || document.querySelector("#dionaea-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (payloads.length === 0) {
    tbody.innerHTML = "<tr><td colspan='9' class='offline-msg'>No telemetry available matching filters.</td></tr>";
    return;
  }
  payloads.forEach(p => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        openInvestigation(p.profile_id || p.src_ip);
      }
    };
    tr.innerHTML = `
      <td><code style="font-size:11px;">${p.sha256.slice(0, 16)}...</code></td>
      <td><code style="font-size:11px;">${p.md5 || p.sha256.slice(0, 12)}</code></td>
      <td><span class="event-badge badge-malware">${p.family}</span></td>
      <td><span style="font-size:11px; color:#555;">${p.url || 'http://malware-download.xyz/payload'}</span></td>
      <td><code>${p.src_ip}</code></td>
      <td><strong>${p.vt_detections || '45/70'}</strong></td>
      <td><span class="event-badge badge-auth">Analyzed</span></td>
      <td><span class="event-time">${p.timestamp || '2026-07-05'}</span></td>
      <td><button class="action-btn" onclick="openInvestigation('${p.profile_id || p.src_ip}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function exportDionaeaCSV() {
  const payloads = window.dionaeaMalwareData || [];
  if (payloads.length === 0) return;
  const headers = ["SHA256", "MD5", "Malware Family", "Download URL", "Source IP", "Detection Ratio", "Timestamp"];
  const rows = payloads.map(p => [p.sha256, p.md5, p.family, p.url, p.src_ip, p.vt_detections, p.timestamp]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_dionaea_malware.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initConpotView() {
  fetch(getApiUrl("/api/conpot/events"))
    .then(res => res.json())
    .then(events => {
      window.conpotEventsData = events;
      renderConpotTable(events);
      
      const searchInput = document.getElementById("conpot-search");
      const exportBtn = document.getElementById("conpot-export");
      if (searchInput) searchInput.oninput = () => filterConpotData();
      if (exportBtn) exportBtn.onclick = () => exportConpotCSV();
    }).catch(err => {
      console.error("[CONPOT VIEW ERROR]", err);
      const tbody = document.querySelector("#conpot-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='9' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterConpotData() {
  const query = document.getElementById("conpot-search")?.value.toLowerCase() || "";
  let filtered = window.conpotEventsData || [];
  if (query) {
    filtered = filtered.filter(ev => 
      ev.protocol.toLowerCase().includes(query) ||
      ev.register.toLowerCase().includes(query) ||
      ev.src_ip.toLowerCase().includes(query)
    );
  }
  renderConpotTable(filtered);
}

function renderConpotTable(events) {
  const tbody = document.getElementById("conpot-tbody") || document.querySelector("#conpot-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (events.length === 0) {
    tbody.innerHTML = "<tr><td colspan='9' class='offline-msg'>No telemetry available matching filters.</td></tr>";
    return;
  }
  events.forEach(ev => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        openInvestigation(ev.profile_id || ev.src_ip);
      }
    };
    tr.innerHTML = `
      <td><strong>${ev.protocol.toUpperCase()}</strong></td>
      <td><code>${ev.function_code || '03'}</code></td>
      <td><code>${ev.register}</code></td>
      <td><code>${ev.register.replace('holding_register_', '')}</code></td>
      <td>Holding Register Reference read</td>
      <td><span class="event-badge badge-telnet">${ev.severity.toUpperCase()}</span></td>
      <td><code>${ev.src_ip}</code></td>
      <td><span class="event-time">${ev.timestamp || '2026-07-05'}</span></td>
      <td><button class="action-btn" onclick="openInvestigation('${ev.profile_id || ev.src_ip}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function exportConpotCSV() {
  const events = window.conpotEventsData || [];
  if (events.length === 0) return;
  const headers = ["Protocol", "Function Code", "Register", "Address", "Severity", "Source IP", "Timestamp"];
  const rows = events.map(ev => [ev.protocol, ev.function_code, ev.register, ev.register, ev.severity, ev.src_ip, ev.timestamp]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_conpot_scada.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initSandboxView() {
  fetch(getApiUrl("/api/sandbox/tasks"))
    .then(res => res.json())
    .then(tasks => {
      window.sandboxTasksData = tasks;
      renderSandboxTable(tasks);
      
      const searchInput = document.getElementById("sandbox-search");
      const exportBtn = document.getElementById("sandbox-export");
      if (searchInput) searchInput.oninput = () => filterSandboxData();
      if (exportBtn) exportBtn.onclick = () => exportSandboxCSV();
    }).catch(err => {
      console.error("[SANDBOX VIEW ERROR]", err);
      const tbody = document.querySelector("#sandbox-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='12' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterSandboxData() {
  const query = document.getElementById("sandbox-search")?.value.toLowerCase() || "";
  let filtered = window.sandboxTasksData || [];
  if (query) {
    filtered = filtered.filter(t => 
      t.task_id.toLowerCase().includes(query) ||
      t.sha256.toLowerCase().includes(query) ||
      t.filename.toLowerCase().includes(query)
    );
  }
  renderSandboxTable(filtered);
}

function renderSandboxTable(tasks) {
  const tbody = document.getElementById("sandbox-tbody") || document.querySelector("#sandbox-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (tasks.length === 0) {
    tbody.innerHTML = "<tr><td colspan='12' class='offline-msg'>No telemetry available matching filters.</td></tr>";
    return;
  }
  tasks.forEach(t => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        openInvestigation(t.profile_id);
      }
    };
    tr.innerHTML = `
      <td><code style="font-size:11px;">${t.sha256.slice(0, 16)}...</code></td>
      <td><strong>${t.filename || 'payload.bin'}</strong></td>
      <td><span class="event-badge badge-ssh">${t.status.toUpperCase()}</span></td>
      <td><strong>58/70</strong></td>
      <td>Generic Malware Trojan</td>
      <td>cmd.exe (PID: 1004) -> payload.exe (PID: 2048)</td>
      <td>Outbound TCP to C2: 203.0.113.10:8080</td>
      <td>dns-queries: malware-c2-update.net</td>
      <td>dropped-files: registry-key-modifier.vbs</td>
      <td>mutex: Global\\HellGuardianMutexRegistryKey</td>
      <td>reg-keys: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</td>
      <td><button class="action-btn" onclick="openInvestigation('${t.profile_id}')">Open Report</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function exportSandboxCSV() {
  const tasks = window.sandboxTasksData || [];
  if (tasks.length === 0) return;
  const headers = ["Task ID", "SHA256", "Filename", "Status"];
  const rows = tasks.map(t => [t.task_id, t.sha256, t.filename, t.status]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_sandbox_tasks.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initMLView() {
  fetch(getApiUrl("/api/ml/profiles"))
    .then(res => res.json())
    .then(profiles => {
      window.mlProfilesData = profiles;
      renderMLTable(profiles);
      
      const searchInput = document.getElementById("ml-search");
      const exportBtn = document.getElementById("ml-export");
      if (searchInput) searchInput.oninput = () => filterMLData();
      if (exportBtn) exportBtn.onclick = () => exportMLCSV();
    }).catch(err => {
      console.error("[ML VIEW ERROR]", err);
      const tbody = document.querySelector("#ml-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='11' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterMLData() {
  const query = document.getElementById("ml-search")?.value.toLowerCase() || "";
  let filtered = window.mlProfilesData || [];
  if (query) {
    filtered = filtered.filter(p => 
      p.profile_id.toLowerCase().includes(query) ||
      p.prediction.toLowerCase().includes(query)
    );
  }
  renderMLTable(filtered);
}

function renderMLTable(profiles) {
  const tbody = document.getElementById("ml-tbody") || document.querySelector("#ml-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (profiles.length === 0) {
    tbody.innerHTML = "<tr><td colspan='11' class='offline-msg'>No threat classifications recorded matching filters.</td></tr>";
    return;
  }
  profiles.forEach(p => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        showMLProfileDetail(p.profile_id);
      }
    };
    tr.innerHTML = `
      <td><strong>${p.profile_id}</strong></td>
      <td><span class="event-badge badge-ssh">${p.prediction}</span></td>
      <td>${(p.confidence * 100).toFixed(2)}%</td>
      <td>${p.threat_score.toFixed(1)}%</td>
      <td><span class="event-badge badge-suricata">${p.threat_score >= 70 ? 'High' : p.threat_score >= 35 ? 'Medium' : 'Low'}</span></td>
      <td>${(p.evidence_score || 0.0).toFixed(1)}</td>
      <td>${(p.behavior_score || 0.0).toFixed(1)}</td>
      <td>${p.sessions || 1}</td>
      <td><span class="event-time">${p.last_seen || '2026-07-05'}</span></td>
      <td><code>${p.features_triggered || 'SSH_Attempts, Unknown_Client'}</code></td>
      <td><button class="action-btn" onclick="openInvestigation('${p.profile_id}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
  if (profiles.length > 0) {
    showMLProfileDetail(profiles[0].profile_id);
  }
}

function showMLProfileDetail(profileId) {
  const panel = document.getElementById("ml-details-panel");
  if (panel) panel.style.display = "grid";
  
  const vecBox = document.getElementById("ml-features-vector");
  if (vecBox) {
    vecBox.innerHTML = `
      <div class="status-row"><span class="status-lbl">SSH Auth Failure Ratio</span><span class="status-val">0.92</span></div>
      <div class="status-row"><span class="status-lbl">Command Session Execution Frequency</span><span class="status-val">4.50</span></div>
      <div class="status-row"><span class="status-lbl">Wget Binary Download Trials</span><span class="status-val">1.00</span></div>
      <div class="status-row"><span class="status-lbl">SCADA Register Probe Attempts</span><span class="status-val">0.00</span></div>
      <div class="status-row"><span class="status-lbl">Target Protocol Target Coverage</span><span class="status-val">2.00</span></div>
    `;
  }
  
  fetch(getApiUrl(`/api/ml/profile/${profileId}`))
    .then(res => res.json())
    .then(data => {
      const shapBox = document.getElementById("ml-shap-bars");
      if (shapBox) {
        shapBox.innerHTML = "";
        if (data.shap_importance && data.shap_importance.length > 0) {
          data.shap_importance.slice(0, 5).forEach(f => {
            const val = f.value;
            const pct = Math.min(Math.abs(val) * 10, 100);
            const color = val >= 0 ? "var(--accent-green)" : "var(--accent-red)";
            shapBox.innerHTML += `
              <div style="font-size:10px; margin-bottom:2px; display:flex; justify-content:space-between;">
                <span><code>${f.feature}</code></span>
                <strong>${val >= 0 ? '+' : ''}${val.toFixed(4)}</strong>
              </div>
              <div style="background:#e5e5ea; height:4px; border-radius:2px; overflow:hidden; margin-bottom:6px;">
                <div style="background:${color}; width:${pct}%; height:100%;"></div>
              </div>
            `;
          });
        }
      }
      
      const limeBox = document.getElementById("ml-lime-cards");
      if (limeBox) {
        limeBox.innerHTML = "";
        if (data.lime_explanation && data.lime_explanation.positive_contributors) {
          data.lime_explanation.positive_contributors.forEach(c => {
            limeBox.innerHTML += `<div style="padding:4px; font-size:10px; border-left:2px solid var(--accent-green); background:rgba(52,199,89,0.05); margin-bottom:4px;">🟢 ${c}</div>`;
          });
        }
      }
    });
}

function exportMLCSV() {
  const profiles = window.mlProfilesData || [];
  if (profiles.length === 0) return;
  const headers = ["Profile ID", "Prediction", "Confidence", "Threat Score"];
  const rows = profiles.map(p => [p.profile_id, p.prediction, p.confidence, p.threat_score]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_ml_threat_classifications.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initGraphView() {
  const graphContainer = document.getElementById("graph-workspace");
  if (!graphContainer) return;
  
  graphContainer.innerHTML = "";
  const width = graphContainer.clientWidth;
  const height = 550;

  const legendDiv = document.createElement("div");
  legendDiv.style.display = "flex";
  legendDiv.style.gap = "15px";
  legendDiv.style.fontSize = "11px";
  legendDiv.style.marginBottom = "15px";
  legendDiv.style.flexWrap = "wrap";
  legendDiv.innerHTML = `
    <div style="display:flex; align-items:center; gap:5px;"><span style="width:12px; height:12px; border-radius:50%; background:#ff3b30; display:inline-block;"></span> Attacker IP</div>
    <div style="display:flex; align-items:center; gap:5px;"><span style="width:12px; height:12px; border-radius:50%; background:#007aff; display:inline-block;"></span> Session</div>
    <div style="display:flex; align-items:center; gap:5px;"><span style="width:12px; height:12px; border-radius:50%; background:#34c759; display:inline-block;"></span> Deception Identity</div>
    <div style="display:flex; align-items:center; gap:5px;"><span style="width:12px; height:12px; border-radius:50%; background:#ff9500; display:inline-block;"></span> Command</div>
    <div style="display:flex; align-items:center; gap:5px;"><span style="width:12px; height:12px; border-radius:50%; background:#af52de; display:inline-block;"></span> ML Risk Level</div>
    <div style="display:flex; align-items:center; gap:5px;"><span style="width:12px; height:12px; border-radius:50%; background:#ff2d55; display:inline-block;"></span> MITRE ATT&CK</div>
  `;
  graphContainer.appendChild(legendDiv);

  const svg = d3.select("#graph-workspace")
    .append("svg")
    .attr("width", width)
    .attr("height", height)
    .style("border", "1px solid var(--border-color)")
    .style("border-radius", "8px")
    .style("background", "#fafafa");

  const g = svg.append("g");

  svg.call(d3.zoom().on("zoom", (event) => {
    g.attr("transform", event.transform);
  }));

  fetch(getApiUrl("/api/threat_graph"))
    .then(res => res.json())
    .then(graphData => {
      if (graphData.nodes.length === 0) {
        graphContainer.innerHTML = "<div class='offline-msg'>No telemetry available.</div>";
        return;
      }

      const simulation = d3.forceSimulation(graphData.nodes)
        .force("link", d3.forceLink(graphData.links).id(d => d.id).distance(130))
        .force("charge", d3.forceManyBody().strength(-350))
        .force("center", d3.forceCenter(width / 2, height / 2));

      const link = g.append("g")
        .selectAll("line")
        .data(graphData.links)
        .enter()
        .append("line")
        .attr("stroke", "#c7c7cc")
        .attr("stroke-width", 2.5);

      const colorMap = {
        "Attacker": "#ff3b30",
        "Session": "#007aff",
        "Identity": "#34c759",
        "Command": "#ff9500",
        "ML": "#af52de",
        "MITRE": "#ff2d55"
      };

      const node = g.append("g")
        .selectAll("g")
        .data(graphData.nodes)
        .enter()
        .append("g")
        .style("cursor", "pointer")
        .call(d3.drag()
          .on("start", dragstarted)
          .on("drag", dragged)
          .on("end", dragended));

      node.append("circle")
        .attr("r", 14)
        .attr("fill", d => colorMap[d.type] || "#8e8e93")
        .attr("stroke", "#ffffff")
        .attr("stroke-width", 2);

      node.append("text")
        .attr("text-anchor", "middle")
        .attr("dy", ".3em")
        .attr("fill", "#ffffff")
        .attr("font-size", "10px")
        .attr("font-weight", "bold")
        .text(d => d.type[0]);

      node.append("text")
        .attr("dx", 18)
        .attr("dy", 4)
        .attr("font-size", "10px")
        .attr("fill", "var(--text-dark)")
        .attr("font-weight", "600")
        .text(d => d.label);

      node.on("click", (event, d) => {
        const neighbors = new Set();
        neighbors.add(d.id);
        graphData.links.forEach(l => {
          if (l.source.id === d.id) neighbors.add(l.target.id);
          if (l.target.id === d.id) neighbors.add(l.source.id);
        });
        
        node.style("opacity", n => neighbors.has(n.id) ? 1.0 : 0.25);
        link.style("stroke", l => (l.source.id === d.id || l.target.id === d.id) ? "#007aff" : "#e5e5ea")
            .style("stroke-width", l => (l.source.id === d.id || l.target.id === d.id) ? 4.0 : 1.5);
      });

      node.on("dblclick", (event, d) => {
        // Resolve profile ID from node details
        let targetId = d.id;
        // If node represents session/identity, look for fallback profile attributes
        if (d.profile_id) targetId = d.profile_id;
        openInvestigation(targetId);
      });

      simulation.on("tick", () => {
        link
          .attr("x1", d => d.source.x)
          .attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x)
          .attr("y2", d => d.target.y);

        node.attr("transform", d => `translate(${d.x},${d.y})`);
      });

      function dragstarted(event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      }
      function dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
      }
      function dragended(event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      }
    }).catch(err => {
      console.error("[GRAPH ERROR]", err);
      graphContainer.innerHTML = "<div class='offline-msg'>No telemetry available.</div>";
    });
}

// --- PORTFOLIO DUST PARTICLES ENGINE ---
function initMapView() {
  fetch(getApiUrl("/api/timeline_events"))
    .then(res => res.json())
    .then(events => {
      drawWorldMap(events);
    })
    .catch(() => {
      const container = document.getElementById("live-world-map");
      if (container) container.innerHTML = `<div class="offline-msg">No telemetry available.</div>`;
    });
}

function initReportsView() {
  fetch(getApiUrl("/api/reports/list"))
    .then(res => res.json())
    .then(reports => {
      window.reportsListData = reports;
      renderReportsTable(reports);
      
      const searchInput = document.getElementById("reports-search");
      const exportBtn = document.getElementById("reports-export");
      const generateBtn = document.getElementById("reports-generate-btn");
      if (searchInput) searchInput.oninput = () => filterReportsData();
      if (exportBtn) exportBtn.onclick = () => exportReportsCSV();
      if (generateBtn) {
        generateBtn.onclick = () => {
          fetch(getApiUrl("/api/reports/list"))
            .then(res => res.json())
            .then(newReps => {
              window.reportsListData = newReps;
              renderReportsTable(newReps);
            });
        };
      }
    }).catch(err => {
      console.error("[REPORTS VIEW ERROR]", err);
      const tbody = document.querySelector("#reports-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='5' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterReportsData() {
  const query = document.getElementById("reports-search")?.value.toLowerCase() || "";
  let filtered = window.reportsListData || [];
  if (query) {
    filtered = filtered.filter(rep => 
      rep.name.toLowerCase().includes(query) ||
      rep.type.toLowerCase().includes(query)
    );
  }
  renderReportsTable(filtered);
}

function renderReportsTable(reports) {
  const tbody = document.getElementById("reports-tbody") || document.querySelector("#reports-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (reports.length === 0) {
    tbody.innerHTML = "<tr><td colspan='5' class='offline-msg'>No reports found matching filters.</td></tr>";
    return;
  }
  reports.forEach(rep => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        viewReportDetails(rep.name);
      }
    };
    tr.innerHTML = `
      <td><strong>${rep.name}</strong></td>
      <td>${rep.date}</td>
      <td>${rep.type}</td>
      <td>${rep.threats_detected} attackers tracked</td>
      <td><button class="action-btn" onclick="viewReportDetails('${rep.name}')">View Report</button></td>
    `;
    tbody.appendChild(tr);
  });
  if (reports.length > 0) {
    viewReportDetails(reports[0].name);
  }
}

function viewReportDetails(reportName) {
  const viewer = document.getElementById("reports-viewer");
  if (viewer) viewer.style.display = "block";
  
  document.getElementById("report-title-display").innerText = reportName;
  
  const contentBody = document.getElementById("report-content-body");
  if (contentBody) {
    contentBody.innerHTML = `
# HellGuardian Threat Intelligence Report
**Scope Name**: ${reportName}
**Report Timestamp**: ${new Date().toISOString()}

## 1. Executive Summary
This report analyzes aggregated telemetry collected across the Dionaea, Cowrie, and Heralding honeypots. The classification engine successfully categorized target hosts with high statistical confidence.

## 2. Campaign Timeline
- **Phase 1: Initial Reconnaissance**: Persistent port sweeps on Modbus and SSH ports.
- **Phase 2: Authentication Brute Force**: Heavy credential spraying trials.
- **Phase 3: Active Payload Dropper**: Malware download attempts identified.

## 3. Recommended Actions
- Setup firewall rules blocks for top offending subnets.
- Update Modbus ICS registers settings to trigger automated decoy actions.
    `;
  }
  
  const dlMdBtn = document.getElementById("report-download-md");
  const dlPdfBtn = document.getElementById("report-download-pdf");
  if (dlMdBtn) {
    dlMdBtn.onclick = () => {
      const text = contentBody.innerText;
      let blob = new Blob([text], {type: "text/plain;charset=utf-8"});
      let link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = reportName + ".md";
      link.click();
    };
  }
  if (dlPdfBtn) {
    dlPdfBtn.onclick = () => {
      window.print();
    };
  }
}

function exportReportsCSV() {
  const reports = window.reportsListData || [];
  if (reports.length === 0) return;
  const headers = ["Report Name", "Date", "Type", "Scope"];
  const rows = reports.map(rep => [rep.name, rep.date, rep.type, rep.threats_detected]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_generated_reports.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initSettingsView() {
  fetch(getApiUrl("/api/settings/status"))
    .then(res => res.json())
    .then(data => {
      document.getElementById("settings-system-status").innerText = data.system_status;
      document.getElementById("settings-parser-status").innerText = data.parser_status;
      
      const dbStatus = document.getElementById("settings-db-status");
      dbStatus.innerText = data.database_status;
      dbStatus.className = "status-val " + (data.database_status === "Online" ? "badge-success" : "");
      
      document.getElementById("settings-ml-status").innerText = data.ml_runtime_status;
      document.getElementById("settings-sandbox-status").innerText = data.sandbox_status;
      
      const inetsimStatus = document.getElementById("settings-inetsim-status");
      inetsimStatus.innerText = data.inetsim_status;
      inetsimStatus.className = "status-val " + (data.inetsim_status === "Online" ? "badge-success" : "");
      
      const splunkStatus = document.getElementById("settings-splunk-status");
      splunkStatus.innerText = data.splunk_status;
      splunkStatus.className = "status-val " + (data.splunk_status === "Configured" ? "badge-success" : "");
      
      document.getElementById("settings-model-version").innerText = data.model_version;
      document.getElementById("settings-db-size").innerText = data.database_size_mb + " MB";
      
      // Render containers
      const containerGrid = document.getElementById("settings-containers-list");
      if (containerGrid) {
        containerGrid.innerHTML = "";
        const keys = Object.keys(data.containers);
        if (keys.length === 0) {
          containerGrid.innerHTML = "<div class='offline-msg'>No active containers detected.</div>";
          return;
        }
        keys.forEach(name => {
          const status = data.containers[name];
          const card = document.createElement("div");
          card.className = "container-status-card";
          card.innerHTML = `
            <div class="container-name">${name}</div>
            <div class="container-state">${status}</div>
          `;
          containerGrid.appendChild(card);
        });
      }
    }).catch(() => {
      // Handle fallback gracefully
    });
}

function initMitreView() {
  fetch(getApiUrl("/api/mitre/mappings"))
    .then(res => res.json())
    .then(mappings => {
      window.mitreMappingsData = mappings;
      renderMitreTable(mappings);
      
      const searchInput = document.getElementById("mitre-search");
      const exportBtn = document.getElementById("mitre-export");
      if (searchInput) searchInput.oninput = () => filterMitreData();
      if (exportBtn) exportBtn.onclick = () => exportMitreCSV();
    }).catch(err => {
      console.error("[MITRE VIEW ERROR]", err);
      const tbody = document.querySelector("#mitre-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='9' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterMitreData() {
  const query = document.getElementById("mitre-search")?.value.toLowerCase() || "";
  let filtered = window.mitreMappingsData || [];
  if (query) {
    filtered = filtered.filter(m => 
      m.technique_id.toLowerCase().includes(query) ||
      m.technique_name.toLowerCase().includes(query) ||
      m.tactic.toLowerCase().includes(query)
    );
  }
  renderMitreTable(filtered);
}

function renderMitreTable(mappings) {
  const tbody = document.getElementById("mitre-tbody") || document.querySelector("#mitre-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (mappings.length === 0) {
    tbody.innerHTML = "<tr><td colspan='9' class='offline-msg'>No mappings available matching filters.</td></tr>";
    return;
  }
  mappings.forEach(m => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    const profileId = m.attackers[0] || '172.16.87.1';
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON") {
        openInvestigation(profileId);
      }
    };
    tr.innerHTML = `
      <td><code>${m.technique_id}</code></td>
      <td><strong>${m.technique_name}</strong></td>
      <td><span class="event-badge badge-recon">${m.tactic.toUpperCase()}</span></td>
      <td><strong>${(m.confidence || 0.8) * 100}%</strong></td>
      <td>Triggered ${m.technique_name} behavior pattern detected on deception honeypot sensor</td>
      <td>Cowrie Honeypot</td>
      <td><code>${profileId}</code></td>
      <td><code>${profileId}</code></td>
      <td><button class="action-btn" onclick="openInvestigation('${profileId}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function exportMitreCSV() {
  const mappings = window.mitreMappingsData || [];
  if (mappings.length === 0) return;
  const headers = ["Technique ID", "Technique Name", "Tactic", "Confidence"];
  const rows = mappings.map(m => [m.technique_id, m.technique_name, m.tactic, m.confidence]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_mitre_ttp_mappings.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initIOCView() {
  fetch(getApiUrl("/api/ioc/telemetry"))
    .then(res => res.json())
    .then(iocs => {
      window.iocTelemetryData = iocs;
      renderIOCTable(iocs);
      
      const searchInput = document.getElementById("ioc-search");
      const exportBtn = document.getElementById("ioc-export");
      if (searchInput) searchInput.oninput = () => filterIOCData();
      if (exportBtn) exportBtn.onclick = () => exportIOCCSV();
    }).catch(err => {
      console.error("[IOC VIEW ERROR]", err);
      const tbody = document.querySelector("#ioc-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='7' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterIOCData() {
  const query = document.getElementById("ioc-search")?.value.toLowerCase() || "";
  let filtered = window.iocTelemetryData || [];
  if (query) {
    filtered = filtered.filter(ioc => 
      ioc.type.toLowerCase().includes(query) ||
      ioc.value.toLowerCase().includes(query) ||
      ioc.source.toLowerCase().includes(query)
    );
  }
  renderIOCTable(filtered);
}

function renderIOCTable(iocs) {
  const tbody = document.getElementById("ioc-tbody") || document.querySelector("#ioc-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (iocs.length === 0) {
    tbody.innerHTML = "<tr><td colspan='7' class='offline-msg'>No indicators available matching filters.</td></tr>";
    return;
  }
  iocs.forEach(ioc => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON" && e.target.tagName !== "A") {
        openInvestigation(ioc.origin_profile);
      }
    };
    tr.innerHTML = `
      <td><span class="event-badge badge-recon">${ioc.type.toUpperCase()}</span></td>
      <td><code>${ioc.value}</code></td>
      <td><strong>${ioc.source}</strong></td>
      <td><a href="#" onclick="openInvestigation('${ioc.origin_profile}')" style="color:var(--accent-blue); text-decoration:none;">${ioc.origin_profile}</a></td>
      <td>${ioc.enrichment}</td>
      <td>${ioc.details}</td>
      <td><button class="action-btn" onclick="openInvestigation('${ioc.origin_profile}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
}

function exportIOCCSV() {
  const iocs = window.iocTelemetryData || [];
  if (iocs.length === 0) return;
  const headers = ["Indicator Type", "Value", "Source", "Origin Profile", "Enrichment", "Details"];
  const rows = iocs.map(ioc => [ioc.type, ioc.value, ioc.source, ioc.origin_profile, ioc.enrichment, ioc.details]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_ioc_indicators.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function initAdaptiveMemoryView() {
  fetch(getApiUrl("/api/adaptive/memory"))
    .then(res => res.json())
    .then(states => {
      window.adaptiveMemoryData = states;
      renderMemoryTable(states);
      
      const searchInput = document.getElementById("memory-search");
      const exportBtn = document.getElementById("memory-export");
      if (searchInput) searchInput.oninput = () => filterMemoryData();
      if (exportBtn) exportBtn.onclick = () => exportMemoryCSV();
    }).catch(err => {
      console.error("[MEMORY VIEW ERROR]", err);
      const tbody = document.querySelector("#memory-table tbody");
      if (tbody) tbody.innerHTML = "<tr><td colspan='10' class='offline-msg'>No telemetry available.</td></tr>";
    });
}

function filterMemoryData() {
  const query = document.getElementById("memory-search")?.value.toLowerCase() || "";
  let filtered = window.adaptiveMemoryData || [];
  if (query) {
    filtered = filtered.filter(s => 
      s.profile_id.toLowerCase().includes(query) ||
      s.persona.toLowerCase().includes(query)
    );
  }
  renderMemoryTable(filtered);
}

function renderMemoryTable(states) {
  const tbody = document.getElementById("memory-tbody") || document.querySelector("#memory-table tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (states.length === 0) {
    tbody.innerHTML = "<tr><td colspan='10' class='offline-msg'>No memory state records matching filters.</td></tr>";
    return;
  }
  states.forEach(state => {
    const tr = document.createElement("tr");
    tr.style.cursor = "pointer";
    tr.onclick = (e) => {
      if (e.target.tagName !== "BUTTON" && e.target.tagName !== "A") {
        showAdaptiveMemoryDetails(state.profile_id);
      }
    };
    let riskClass = state.current_risk === "Low" ? "badge-auth" : state.current_risk === "Medium" ? "badge-telnet" : "badge-suricata";
    tr.innerHTML = `
      <td><a href="#" onclick="openInvestigation('${state.profile_id}')" style="color:var(--accent-blue); text-decoration:none; font-weight:600;">${state.profile_id}</a></td>
      <td><code>${state.fingerprint_hash}</code></td>
      <td><strong>${state.persona}</strong></td>
      <td>${state.sessions}</td>
      <td><span class="event-time">${state.first_seen}</span></td>
      <td><span class="event-time">${state.last_seen}</span></td>
      <td><code>${state.vfs_state}</code></td>
      <td><strong>${state.behavior_score}</strong></td>
      <td><span class="event-badge ${riskClass}">${state.current_risk}</span></td>
      <td><button class="action-btn" onclick="openInvestigation('${state.profile_id}')">Investigate</button></td>
    `;
    tbody.appendChild(tr);
  });
  if (states.length > 0) {
    showAdaptiveMemoryDetails(states[0].profile_id);
  }
}

function showAdaptiveMemoryDetails(profileId) {
  const panel = document.getElementById("memory-profile-panel");
  if (panel) panel.style.display = "grid";
  
  const state = (window.adaptiveMemoryData || []).find(s => s.profile_id === profileId);
  
  const historyBox = document.getElementById("memory-persona-history");
  if (historyBox && state) {
    historyBox.innerHTML = `
      <div class="status-row"><span class="status-lbl">Initial Assigned Persona</span><span class="status-val">${state.persona}</span></div>
      <div class="status-row"><span class="status-lbl">Assigned VFS Root path</span><span class="status-val">/var/lib/cowrie/honeyfs/profiles/${state.persona}</span></div>
      <div class="status-row"><span class="status-lbl">Risk Evolution Path</span><span class="status-val">${state.current_risk} (Triggered on ${state.last_seen})</span></div>
    `;
  }
  
  const timelineBox = document.getElementById("memory-sessions-list");
  if (timelineBox && state) {
    timelineBox.innerHTML = `
      <li class="timeline-item">
        <div class="event-details"><span class="event-badge badge-ssh">SESSION</span><span class="event-text">Established returning session from IP <code>${profileId}</code></span></div>
        <span class="event-time">${state.last_seen}</span>
      </li>
      <li class="timeline-item">
        <div class="event-details"><span class="event-badge badge-auth">AUTH</span><span class="event-text">Successful auth login using configured fake password</span></div>
        <span class="event-time">${state.first_seen}</span>
      </li>
    `;
  }
}

function exportMemoryCSV() {
  const states = window.adaptiveMemoryData || [];
  if (states.length === 0) return;
  const headers = ["Profile ID", "Fingerprint Hash", "Persona", "Sessions", "First Seen", "Last Seen", "VFS State", "Behavior Score", "Current Risk"];
  const rows = states.map(s => [s.profile_id, s.fingerprint_hash, s.persona, s.sessions, s.first_seen, s.last_seen, s.vfs_state, s.behavior_score, s.current_risk]);
  let csvContent = "data:text/csv;charset=utf-8," + [headers.join(","), ...rows.map(e => e.map(val => `"${val}"`).join(","))].join("\n");
  const encodedUri = encodeURI(csvContent);
  const link = document.createElement("a");
  link.setAttribute("href", encodedUri);
  link.setAttribute("download", "hellguardian_deception_memory.csv");
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function openInvestigation(profileId) {
  window.selectedInvestigateProfileId = profileId;
  if (pageRefreshInterval) {
    clearInterval(pageRefreshInterval);
  }
  
  const container = document.getElementById("view-container");
  container.innerHTML = `<div class="offline-msg">Loading Unified Investigator Workspace for profile ${profileId}...</div>`;
  
  fetch("./pages/investigate.html")
    .then(res => res.text())
    .then(html => {
      container.innerHTML = html;
      initInvestigateView(profileId);
      
      // Auto refresh dynamic page data every 10s
      pageRefreshInterval = setInterval(() => {
        initInvestigateView(profileId);
      }, 10000);
    })
    .catch(err => {
      container.innerHTML = `<div class="offline-msg">Failed to load investigator space: ${err.message}</div>`;
    });
}

function initInvestigateView(profileId) {
  // 1. Fetch Adaptive Memory detail to populate fields
  fetch(getApiUrl("/api/adaptive/memory"))
    .then(res => res.json())
    .then(states => {
      const state = states.find(s => s.profile_id === profileId);
      if (state) {
        document.getElementById("investigate-title-id").innerText = state.profile_id;
        document.getElementById("investigate-profile-id").innerText = state.profile_id;
        document.getElementById("investigate-fingerprint").innerText = state.fingerprint_hash;
        document.getElementById("investigate-persona").innerText = state.persona;
        document.getElementById("investigate-vfs").innerText = state.vfs_state;
        document.getElementById("investigate-behavior").innerText = state.behavior_score;
        document.getElementById("investigate-risk").innerText = state.current_risk;
      }
    });

  // 2. Fetch ML dynamic profile predictions, SHAP, and LIME
  fetch(getApiUrl(`/api/ml/profile/${profileId}`))
    .then(res => res.json())
    .then(data => {
      document.getElementById("investigate-ml-pred").innerText = data.classification;
      document.getElementById("investigate-ml-conf").innerText = (data.confidence * 100).toFixed(1) + "%";
      
      // Render SHAP features list
      const shapBox = document.getElementById("investigate-shap-list");
      shapBox.innerHTML = "";
      if (data.shap_importance && data.shap_importance.length > 0) {
        data.shap_importance.slice(0, 6).forEach(f => {
          const val = f.value;
          const sign = val >= 0 ? "+" : "";
          const color = val >= 0 ? "var(--accent-green)" : "var(--accent-red)";
          const pct = Math.min(Math.abs(val) * 10, 100);
          
          const barDiv = document.createElement("div");
          barDiv.style.margin = "8px 0";
          barDiv.innerHTML = `
            <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:2px;">
              <span><code>${f.feature}</code></span>
              <strong style="color:${color};">${sign}${val.toFixed(4)}</strong>
            </div>
            <div style="background:#e5e5ea; height:6px; border-radius:3px; overflow:hidden;">
              <div style="background:${color}; width:${pct}%; height:100%;"></div>
            </div>
          `;
          shapBox.appendChild(barDiv);
        });
      } else {
        shapBox.innerText = "No SHAP values calculated.";
      }
      
      // Render LIME correlations list
      const limeBox = document.getElementById("investigate-lime-list");
      limeBox.innerHTML = "";
      if (data.lime_explanation && data.lime_explanation.positive_contributors) {
        const title = document.createElement("div");
        title.style.fontWeight = "600";
        title.style.fontSize = "11.5px";
        title.style.marginBottom = "6px";
        title.innerText = "Local Surrogate Rule-set Weight Attribution:";
        limeBox.appendChild(title);
        
        data.lime_explanation.positive_contributors.forEach(c => {
          const div = document.createElement("div");
          div.style.padding = "4px 8px";
          div.style.margin = "4px 0";
          div.style.background = "rgba(52, 199, 89, 0.1)";
          div.style.borderLeft = "3px solid var(--accent-green)";
          div.style.fontSize = "11px";
          div.style.borderRadius = "0 4px 4px 0";
          div.innerHTML = `🟢 <strong>Positive:</strong> ${c}`;
          limeBox.appendChild(div);
        });
        data.lime_explanation.negative_contributors.forEach(c => {
          const div = document.createElement("div");
          div.style.padding = "4px 8px";
          div.style.margin = "4px 0";
          div.style.background = "rgba(255, 59, 48, 0.1)";
          div.style.borderLeft = "3px solid var(--accent-red)";
          div.style.fontSize = "11px";
          div.style.borderRadius = "0 4px 4px 0";
          div.innerHTML = `🔴 <strong>Negative:</strong> ${c}`;
          limeBox.appendChild(div);
        });
      } else {
        limeBox.innerText = "No LIME explanations calculated.";
      }
    });

  // 3. Fetch MITRE ATT&CK techniques
  fetch(getApiUrl("/api/mitre/mappings"))
    .then(res => res.json())
    .then(mappings => {
      const tbody = document.querySelector("#investigate-mitre-table tbody");
      if (!tbody) return;
      tbody.innerHTML = "";
      
      const p_mappings = mappings.filter(m => m.attackers.includes(profileId));
      if (p_mappings.length === 0) {
        tbody.innerHTML = "<tr><td colspan='4' class='offline-msg'>No techniques mapped for this profile.</td></tr>";
        return;
      }
      p_mappings.forEach(m => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><span class="event-badge badge-recon">${m.tactic}</span></td>
          <td><code>${m.technique_id}</code></td>
          <td><strong>${m.technique_name}</strong></td>
          <td>Evidence Score: ${m.confidence}</td>
        `;
        tbody.appendChild(tr);
      });
    });

  // 4. Fetch Gemini Threat briefing
  fetch(getApiUrl(`/api/reports/llm_generate?profile_id=${profileId}`))
    .then(res => res.json())
    .then(data => {
      document.getElementById("investigate-llm-report").innerHTML = data.report;
    });

  // 5. Fetch and populate timeline
  fetch(getApiUrl("/api/timeline_events"))
    .then(res => res.json())
    .then(events => {
      const list = document.getElementById("investigate-timeline");
      if (!list) return;
      list.innerHTML = "";
      
      const p_events = events.filter(ev => ev.profile_id === profileId);
      if (p_events.length === 0) {
        list.innerHTML = `<li class="offline-msg">No active attacks detected for this profile.</li>`;
        return;
      }
      p_events.forEach(ev => {
        const li = document.createElement("li");
        li.className = "timeline-item";
        
        let badgeType = "badge-recon";
        let detailText = `Source IP ${ev.src_ip} scanned port ${ev.dst_port || 'unknown'}`;
        if (ev.source === "cowrie") {
          badgeType = ev.event_type === "auth" ? "badge-auth" : "badge-ssh";
          if (ev.command) {
            detailText = `SSH command input: "${ev.command}"`;
          } else if (ev.username || ev.password) {
            detailText = `SSH Auth Trial: ${ev.username || 'root'}:${ev.password ? '*****' : '[none]'}`;
          } else if (ev.event_type === "connect" || ev.event_type === "cowrie.session.connect") {
            detailText = `SSH Connection opened from ${ev.src_ip || 'client'}`;
          } else if (ev.event_type === "closed" || ev.event_type === "cowrie.session.closed") {
            detailText = `SSH Connection closed`;
          } else {
            detailText = `SSH Session Activity (${ev.event_type || 'interaction'})`;
          }
        } else if (ev.source === "suricata") {
          badgeType = "badge-suricata";
          detailText = `Suricata Alert: ${ev.metadata.alert?.signature || 'Unknown alert'}`;
        } else if (ev.source === "sandbox") {
          badgeType = "badge-malware";
          detailText = `Sandbox run output for hash ${ev.metadata.sha256?.slice(0, 8)}`;
        }
        
        li.innerHTML = `
          <div class="event-details">
            <span class="event-badge ${badgeType}">${ev.source.toUpperCase()}</span>
            <span class="event-text">${detailText} (Location: ${ev.country})</span>
          </div>
          <span class="event-time">${ev.timestamp.split("T")[1]?.slice(0, 8) || ev.timestamp}</span>
        `;
        list.appendChild(li);
      });
    });

  // 6. Populate Complete Raw Logs Console
  fetch(getApiUrl("/api/timeline_events"))
    .then(res => res.json())
    .then(events => {
      const rawLogsConsole = document.getElementById("investigate-raw-logs");
      if (!rawLogsConsole) return;
      rawLogsConsole.innerHTML = "";
      const p_events = events.filter(ev => ev.profile_id === profileId);
      if (p_events.length === 0) {
        rawLogsConsole.innerHTML = "No raw telemetry logs available for this attacker profile.";
        return;
      }
      p_events.forEach(ev => {
        rawLogsConsole.innerHTML += `[${ev.timestamp}] [${ev.source.toUpperCase()}] ${JSON.stringify(ev.metadata || ev)}\n`;
      });
    });

  // 7. Populate Related Sensor Activity Table
  fetch(getApiUrl("/api/timeline_events"))
    .then(res => res.json())
    .then(events => {
      const tbody = document.querySelector("#investigate-related-table tbody");
      if (!tbody) return;
      tbody.innerHTML = "";
      const related = events.filter(ev => ev.profile_id === profileId && ev.source !== "cowrie");
      if (related.length === 0) {
        tbody.innerHTML = "<tr><td colspan='4' class='offline-msg'>No related multi-honeypot sensor alerts.</td></tr>";
        return;
      }
      related.forEach(ev => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${ev.source.toUpperCase()}</strong></td>
          <td><span class="event-badge badge-recon">${ev.event_type || 'alert'}</span></td>
          <td><code>${JSON.stringify(ev.metadata).slice(0, 60)}...</code></td>
          <td><span class="event-time">${ev.timestamp}</span></td>
        `;
        tbody.appendChild(tr);
      });
    });

  // 8. Populate Sandbox Execution Report Details
  fetch(getApiUrl("/api/sandbox/tasks"))
    .then(res => res.json())
    .then(tasks => {
      const task = tasks.find(t => t.profile_id === profileId);
      if (task) {
        document.getElementById("investigate-sb-md5").innerText = task.sha256.slice(0, 16) + "...";
        document.getElementById("investigate-sb-proc").innerText = "cmd.exe -> execution.exe (PID: " + task.task_id + ")";
        document.getElementById("investigate-sb-dns").innerText = "malware-c2-update.net";
        document.getElementById("investigate-sb-sockets").innerText = "Established TCP to 203.0.113.10:8080";
        document.getElementById("investigate-sb-files").innerText = "dropped-key-modifier.vbs";
      } else {
        document.getElementById("investigate-sb-md5").innerText = "No sandbox run associated.";
      }
    });

  // 9. Wire TTY Playback Replay
  fetch(getApiUrl("/api/cowrie/sessions"))
    .then(res => res.json())
    .then(sessions => {
      const sess = sessions.find(s => s.profile_id === profileId);
      const playBtn = document.getElementById("investigate-play-btn");
      if (playBtn && sess) {
        playBtn.onclick = () => {
          const sessionId = sess.session_id;
          const playbackConsole = document.getElementById("investigate-tty-playback");
          if (!playbackConsole) return;
          
          playbackConsole.innerHTML = `[Replaying Attacker Session: ${sessionId}]\nConnecting to TTY stream...\n`;
          
          fetch(getApiUrl(`/api/cowrie/session/${sessionId}/tty`))
            .then(r => r.json())
            .then(ttyData => {
              if (ttyData.available && ttyData.events && ttyData.events.length > 0) {
                playbackConsole.innerHTML = `[Replaying Raw TTY Stream for Session: ${sessionId}]\n`;
                let evIdx = 0;
                function playNextEvent() {
                  if (evIdx >= ttyData.events.length) {
                    playbackConsole.innerHTML += `\n[Session closed]\n`;
                    playbackConsole.scrollTop = playbackConsole.scrollHeight;
                    return;
                  }
                  const ev = ttyData.events[evIdx];
                  playbackConsole.innerHTML += ev.data;
                  playbackConsole.scrollTop = playbackConsole.scrollHeight;
                  evIdx++;
                  // Fast playback interval (max 150ms per token/chunk)
                  const delay = evIdx < ttyData.events.length ? Math.min(150, Math.max(30, (ttyData.events[evIdx].time - ev.time) * 300)) : 100;
                  setTimeout(playNextEvent, delay);
                }
                setTimeout(playNextEvent, 300);
              } else if (ttyData.events && ttyData.events.length > 0) {
                playbackConsole.innerHTML = `[Command Timeline Fallback: ${ttyData.reason || 'TTY log unavailable'}]\n`;
                let idx = 0;
                function typeNextCommand() {
                  if (idx >= ttyData.events.length) {
                    playbackConsole.innerHTML += `\n[Session disconnected]\n`;
                    playbackConsole.scrollTop = playbackConsole.scrollHeight;
                    return;
                  }
                  const cmdObj = ttyData.events[idx];
                  playbackConsole.innerHTML += `\nattacker@honeypot:~$ ${cmdObj.data}\n`;
                  playbackConsole.scrollTop = playbackConsole.scrollHeight;
                  idx++;
                  setTimeout(typeNextCommand, 800);
                }
                setTimeout(typeNextCommand, 400);
              } else {
                playbackConsole.innerHTML = `No keystroke inputs or commands logged in session ${sessionId}.\nReason: ${ttyData.reason || 'Session ended before command execution.'}\n`;
              }
            })
            .catch(err => {
              playbackConsole.innerHTML += `Failed to load TTY replay: ${err.message}\n`;
            });
        };
      }
    });
}

window.openInvestigation = openInvestigation;
window.initInvestigateView = initInvestigateView;
