const $ = (id) => document.getElementById(id);

function setText(id, value) {
    const el = $(id);
    if (el) el.textContent = value;
}

function formatTimestamp(value) {
    if (!value) return "—";

    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;

    return date.toLocaleString("es-EC");
}

function updateServerState(isOnline) {
    const dot = $("server-dot");
    const text = $("server-text");

    if (isOnline) {
        dot.classList.remove("offline");
        dot.classList.add("online");
        text.textContent = "ONLINE";
    } else {
        dot.classList.remove("online");
        dot.classList.add("offline");
        text.textContent = "SIN CONEXIÓN";
    }
}

function setBadge(id, text, tone) {
    const el = $(id);
    el.textContent = text;
    el.className = `badge ${tone}`;
}

function updateCryptoStatus(metrics) {
    const status = metrics.crypto_status || "ESPERANDO";
    const value = $("crypto-status");

    value.textContent = status;
    value.classList.remove("waiting", "valid", "rejected");

    if (status === "VALIDO") {
        value.classList.add("valid");
        setBadge("crypto-badge", "TAG VÁLIDO", "safe");
        setText("crypto-error", "El ciphertext fue autenticado y descifrado correctamente.");
    } else if (status === "RECHAZADO") {
        value.classList.add("rejected");
        setBadge("crypto-badge", "PAQUETE RECHAZADO", "danger");
        setText(
            "crypto-error",
            metrics.last_error || "La autenticación criptográfica no pudo validarse."
        );
    } else {
        value.classList.add("waiting");
        setBadge("crypto-badge", "SIN PAQUETE", "neutral");
        setText("crypto-error", "El servidor aún no ha procesado tráfico cifrado.");
    }
}

function updateSensorStatus(status) {
    if (status === "NORMAL") {
        setBadge("sensor-status", "NIVEL NORMAL", "safe");
    } else if (status === "ALERTA") {
        setBadge("sensor-status", "ALERTA", "warn");
    } else if (status === "CRITICO") {
        setBadge("sensor-status", "NIVEL CRÍTICO", "danger");
    } else if (status === "DATO_RECIBIDO") {
        setBadge("sensor-status", "DATO RECIBIDO", "info");
    } else {
        setBadge("sensor-status", "SIN DATOS", "neutral");
    }
}

function drawLine(id, values, fixedMax = null) {
    const polyline = $(id);

    if (!Array.isArray(values) || values.length === 0) {
        polyline.setAttribute("points", "");
        return;
    }

    const x0 = 30;
    const x1 = 575;
    const yTop = 24;
    const yBottom = 160;

    let maxValue = fixedMax ?? Math.max(...values, 1);

    if (!Number.isFinite(maxValue) || maxValue <= 0) {
        maxValue = 1;
    }

    const step = values.length === 1 ? 0 : (x1 - x0) / (values.length - 1);

    const points = values.map((rawValue, index) => {
        const value = Number(rawValue) || 0;
        const x = x0 + index * step;
        const ratio = Math.max(0, Math.min(1, value / maxValue));
        const y = yBottom - ratio * (yBottom - yTop);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    polyline.setAttribute("points", points.join(" "));
}

async function checkHealth() {
    try {
        const response = await fetch("/api/health", { cache: "no-store" });
        if (!response.ok) throw new Error("health check failed");

        updateServerState(true);
        setText(
            "transport-label",
            window.location.protocol === "https:" ? "HTTPS" : "HTTP LOCAL"
        );
    } catch (error) {
        updateServerState(false);
    }
}

async function updateDashboard() {
    try {
        const response = await fetch("/api/metrics", { cache: "no-store" });
        if (!response.ok) throw new Error("metrics request failed");

        const data = await response.json();
        const metrics = data.metrics;

        updateServerState(true);
        updateCryptoStatus(metrics);
        updateSensorStatus(metrics.sensor_status);

        setText("adc-value", metrics.adc ?? "—");
        setText(
            "voltage-value",
            metrics.voltage === null || metrics.voltage === undefined
                ? "—"
                : `${Number(metrics.voltage).toFixed(4)} V`
        );

        setText("latency-value", `${metrics.latency ?? 0} ms`);
        setText("cpu-value", `${Number(metrics.esp_cpu ?? 0).toFixed(2)} %`);

        setText("ciphertext-value", metrics.raw_ciphertext || "-");
        setText("client-pub-value", metrics.client_pub_preview || "-");
        setText("nonce-value", metrics.nonce_preview || "-");
        setText("tag-value", metrics.tag_preview || "-");

        setText("packet-count", metrics.packet_count ?? 0);
        setText("last-update", formatTimestamp(metrics.last_update));

        setText("latency-last", `${metrics.latency ?? 0} ms`);
        setText("cpu-last", `${Number(metrics.esp_cpu ?? 0).toFixed(2)} %`);

        drawLine("latency-line", data.history_latency);
        drawLine("cpu-line", data.history_cpu, 100);

        setText(
            "footer-state",
            metrics.last_update
                ? `Última sincronización: ${formatTimestamp(metrics.last_update)}`
                : "Servidor listo · esperando ESP32"
        );
    } catch (error) {
        updateServerState(false);
        setText("footer-state", "No se pudo actualizar el dashboard");
    }
}

checkHealth();
updateDashboard();

setInterval(updateDashboard, 1000);
setInterval(checkHealth, 10000);
