        // ===== AOS INIT =====
        AOS.init({ duration: 600, once: true });

        // ===== LOGIN REDIRECT =====
        if (!localStorage.getItem("token")) {
            window.location.href = "login.html";
        }

        // ===== DOM REFS =====
        const accountMenu = document.getElementById("accountMenu");
        const themeBtn = document.getElementById("themeBtn");
        const userNameSpan = document.getElementById("userName");
        const userEmailSpan = document.getElementById("userEmail");
        const userAvatar = document.getElementById("userAvatar");
        const authBtn = document.getElementById("authBtn");
        const accountBtn = document.getElementById("accountBtn");

        // ===== DASHBOARD REFS =====
        const threatsBlockedEl = document.getElementById("threatsBlocked");
        const scansRunEl = document.getElementById("scansRun");
        const securityScoreEl = document.getElementById("securityScore");
        const uptimeEl = document.getElementById("uptime");
        const threatFill = document.getElementById("threatFill");
        const threatBadge = document.getElementById("threatBadge");
        const threatDesc = document.getElementById("threatDesc");
        const scanBtn = document.getElementById("scanBtn");
        const scanStatus = document.getElementById("scanStatus");
        const scanProgress = document.getElementById("scanProgress");
        const scanResults = document.getElementById("scanResults");
        const activityList = document.getElementById("activityList");
        const clearActivity = document.getElementById("clearActivity");
        const sysStatus = document.getElementById("sysStatus");

        // ===== STATE =====
        let threatsBlocked = 0;
        let scansRun = 0;
        let securityScore = 98;
        let uptimeSeconds = 0;
        let uptimeInterval = null;
        let threatInterval = null;
        let isScanning = false;

        // ===== ACCOUNT UI =====
        function updateUI() {
            const userEmail = localStorage.getItem("userEmail");
            const userName = localStorage.getItem("userName");
            if (userEmail && userName) {
                userNameSpan.textContent = userName;
                userEmailSpan.textContent = userEmail;
                const firstLetter = userName.charAt(0).toUpperCase();
                userAvatar.innerHTML = `<span>${firstLetter}</span>`;
                accountBtn.textContent = firstLetter;
                authBtn.textContent = "Logout";
            } else {
                userNameSpan.textContent = "Guest";
                userEmailSpan.textContent = "guest@cybershield.local";
                userAvatar.textContent = "G";
                accountBtn.textContent = "👤";
                authBtn.textContent = "Login";
            }
        }

        function logout() {
            localStorage.removeItem("token");
            localStorage.removeItem("userEmail");
            localStorage.removeItem("userName");
            window.location.href = "login.html";
        }

        authBtn?.addEventListener("click", (e) => {
            e.preventDefault();
            if (localStorage.getItem("token")) {
                logout();
            } else {
                window.location.href = "login.html";
            }
        });

        accountBtn?.addEventListener('click', (e) => {
            e.stopPropagation();
            accountMenu.classList.toggle('show');
        });

        document.addEventListener('click', (e) => {
            if (!accountBtn?.contains(e.target) && !accountMenu?.contains(e.target)) {
                accountMenu?.classList.remove('show');
            }
        });

        // ===== THEME =====
        function updateThemeIcon() {
            themeBtn.textContent = document.body.classList.contains('light-mode') ? '☀️' : '🌙';
        }

        function toggleTheme() {
            document.body.classList.toggle('light-mode');
            localStorage.setItem('theme', document.body.classList.contains('light-mode') ? 'light' : 'dark');
            updateThemeIcon();
        }
        themeBtn?.addEventListener('click', toggleTheme);
        if (localStorage.getItem('theme') === 'light') {
            document.body.classList.add('light-mode');
        }
        updateUI();
        updateThemeIcon();

        // ===== HELPERS =====
        function formatTime(sec) {
            const h = Math.floor(sec / 3600);
            const m = Math.floor((sec % 3600) / 60);
            if (h > 0) return `${h}h ${m}m`;
            return `${m}m`;
        }

        function addActivity(icon, text) {
            const item = document.createElement('div');
            item.className = 'activity-item';
            const now = new Date();
            const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            item.innerHTML = `
                <span class="activity-icon">${icon}</span>
                <span class="activity-text">${text}</span>
                <span class="activity-time">${timeStr}</span>
            `;
            activityList.prepend(item);
            // Keep list manageable
            while (activityList.children.length > 20) {
                activityList.removeChild(activityList.lastChild);
            }
        }

        function updateThreatLevel(value) {
            // value: 0-100
            threatFill.style.width = Math.min(value, 100) + '%';
            let label, desc, color;
            if (value < 25) {
                label = 'LOW';
                desc = 'All systems nominal. No active threats detected.';
                color = '#22c55e';
                threatFill.style.background = 'linear-gradient(90deg, #22c55e, #4ade80)';
            } else if (value < 50) {
                label = 'ELEVATED';
                desc = 'Some suspicious activity detected. Monitoring in progress.';
                color = '#f59e0b';
                threatFill.style.background = 'linear-gradient(90deg, #f59e0b, #fbbf24)';
            } else if (value < 75) {
                label = 'HIGH';
                desc = 'Active threats detected! Immediate action recommended.';
                color = '#ef4444';
                threatFill.style.background = 'linear-gradient(90deg, #ef4444, #f87171)';
            } else {
                label = 'CRITICAL';
                desc = '🚨 CRITICAL: System under active attack! Take immediate action.';
                color = '#b91c1c';
                threatFill.style.background = 'linear-gradient(90deg, #b91c1c, #dc2626)';
            }
            threatBadge.textContent = label;
            threatBadge.style.color = color;
            threatBadge.style.borderColor = color;
            threatDesc.textContent = desc;

            // Update system status
            const dot = sysStatus.querySelector('.status-dot');
            const labelEl = sysStatus.querySelector('.status-label');
            if (value < 25) {
                dot.className = 'status-dot online';
                labelEl.textContent = 'Secure';
            } else if (value < 50) {
                dot.className = 'status-dot warning';
                labelEl.textContent = 'Monitoring';
            } else {
                dot.className = 'status-dot offline';
                labelEl.textContent = 'Threat Detected!';
            }
        }

        // ===== RANDOM THREAT FLUCTUATION =====
        function randomThreatUpdate() {
            const current = parseFloat(threatFill.style.width) || 12;
            const delta = (Math.random() - 0.5) * 8;
            let newVal = Math.max(2, Math.min(92, current + delta));
            // Occasionally spike
            if (Math.random() < 0.08) {
                newVal = Math.min(92, newVal + 20 + Math.random() * 20);
                addActivity('⚠️', 'Spike in suspicious network traffic detected!');
            }
            // Occasionally drop
            if (Math.random() < 0.05) {
                newVal = Math.max(2, newVal - 15);
                addActivity('✅', 'Threat level decreasing — systems stabilizing.');
            }
            updateThreatLevel(newVal);
        }

        // ===== QUICK SCAN =====
        scanBtn?.addEventListener('click', () => {
            if (isScanning) return;
            isScanning = true;
            scanBtn.disabled = true;
            scanBtn.innerHTML = '<i class="bi bi-arrow-repeat spin"></i> Scanning...';
            scanStatus.textContent = 'Scanning...';
            scanStatus.style.color = 'var(--accent)';
            scanProgress.style.width = '0%';
            scanResults.innerHTML = '';
            scanResults.className = 'scan-results';

            let progress = 0;
            const scanInterval = setInterval(() => {
                progress += 2 + Math.random() * 4;
                if (progress >= 100) {
                    progress = 100;
                    clearInterval(scanInterval);
                    // Scan complete
                    const threatsFound = Math.floor(Math.random() * 5);
                    const isClean = threatsFound === 0;
                    scansRun++;
                    scansRunEl.textContent = scansRun;
                    if (isClean) {
                        scanResults.innerHTML = `
                            <div class="scan-result clean">
                                <i class="bi bi-check-circle-fill"></i> Scan complete — <strong>No threats found</strong>. System is clean.
                            </div>
                        `;
                        addActivity('✅', 'Quick scan completed — 0 threats detected.');
                        // Small security score boost
                        securityScore = Math.min(100, securityScore + 1);
                        securityScoreEl.textContent = securityScore;
                    } else {
                        const blocked = threatsFound;
                        threatsBlocked += blocked;
                        threatsBlockedEl.textContent = threatsBlocked;
                        scanResults.innerHTML = `
                            <div class="scan-result threat">
                                <i class="bi bi-exclamation-triangle-fill"></i> Scan complete — <strong>${blocked} threat${blocked > 1 ? 's' : ''} found</strong> and neutralized.
                            </div>
                        `;
                        addActivity(`🛡️`, `Quick scan found and blocked ${blocked} threat${blocked > 1 ? 's' : ''}.`);
                        securityScore = Math.max(50, securityScore - 2);
                        securityScoreEl.textContent = securityScore;
                        // Spike threat level
                        const current = parseFloat(threatFill.style.width) || 12;
                        const spike = Math.min(90, current + 10 + Math.random() * 15);
                        updateThreatLevel(spike);
                    }
                    scanStatus.textContent = 'Done';
                    scanStatus.style.color = '#22c55e';
                    scanBtn.innerHTML = '<i class="bi bi-shield-check"></i> Run Scan';
                    scanBtn.disabled = false;
                    isScanning = false;
                }
                scanProgress.style.width = Math.min(progress, 100) + '%';
            }, 60 + Math.random() * 40);
        });

        // ===== UPTIME COUNTER =====
        uptimeInterval = setInterval(() => {
            uptimeSeconds++;
            uptimeEl.textContent = formatTime(uptimeSeconds);
        }, 1000);

        // ===== THREAT FLUCTUATION =====
        threatInterval = setInterval(randomThreatUpdate, 4000);

        // ===== ACTIVITY CLEAR =====
        clearActivity?.addEventListener('click', () => {
            activityList.innerHTML = '';
            addActivity('🔄', 'Activity log cleared.');
        });

        // ===== INITIAL SETUP =====
        // Random initial stats
        threatsBlocked = Math.floor(Math.random() * 40) + 10;
        scansRun = Math.floor(Math.random() * 60) + 20;
        threatsBlockedEl.textContent = threatsBlocked;
        scansRunEl.textContent = scansRun;
        securityScore = 92 + Math.floor(Math.random() * 7);
        securityScoreEl.textContent = securityScore;

        // Initial threat level
        const initialThreat = 8 + Math.random() * 14;
        updateThreatLevel(initialThreat);

        // Seed activity
        addActivity('🛡️', 'CyberShield AI engine initialized — v3.2.1');
        addActivity('🔒', 'Secure tunnel established to threat intelligence feed.');
        addActivity('📡', 'Monitoring 12,847 network endpoints.');

        // ===== KEYBOARD SHORTCUT: Ctrl+Shift+S =====
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.shiftKey && (e.key === 's' || e.key === 'S')) {
                e.preventDefault();
                scanBtn?.click();
            }
        });

        // ===== CONSOLE EASTER EGG =====
        console.log('%c🛡️ CyberShield Hub v3.2.1', 'font-size:20px; font-weight:bold; color:#3b82f6;');
        console.log('%c🔒 Security is everyone\'s responsibility.', 'font-size:14px; color:#94a3b8;');
        console.log('%c⚡ Press Ctrl+Shift+S for a quick scan!', 'font-size:14px; color:#22c55e;');

        console.log('✅ Dashboard interactive features loaded.');