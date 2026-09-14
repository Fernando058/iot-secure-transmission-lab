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

function updateDeviceState(metrics) {
    const dot = $("device-dot");
    const text = $("device-text");
    const age = $("device-age");
    const sessionState = $("session-device-status");

    const status = metrics.device_status || "SIN_DATOS";
    const seconds = metrics.device_age_s;

    dot.classList.remove("online", "offline", "delayed");

    if (status === "ACTIVO") {
        dot.classList.add("online");
        text.textContent = "ACTIVO";
        age.textContent = seconds === null ? "Recibiendo datos" : `Último paquete hace ${seconds} s`;
        sessionState.textContent = "ACTIVO";
    } else if (status === "RETRASADO") {
        dot.classList.add("delayed");
        text.textContent = "SIN RESPUESTA RECIENTE";
        age.textContent = `Último paquete hace ${seconds} s`;
        sessionState.textContent = "RETRASADO";
    } else if (status === "DESCONECTADO") {
        dot.classList.add("offline");
        text.textContent = "DESCONECTADO";
        age.textContent = `Último paquete hace ${seconds} s`;
        sessionState.textContent = "DESCONECTADO";
    } else {
        dot.classList.add("offline");
        text.textContent = "SIN DATOS";
        age.textContent = "Aún no se recibe telemetría";
        sessionState.textContent = "SIN DATOS";
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
        setText(
            "crypto-error",
            "El ciphertext fue autenticado y descifrado correctamente."
        );
    } else if (status === "RECHAZADO") {
        value.classList.add("rejected");
        setBadge("crypto-badge", "PAQUETE RECHAZADO", "danger");
        setText(
            "crypto-error",
            metrics.last_error ||
                "La autenticación criptográfica no pudo validarse."
        );
    } else {
        value.classList.add("waiting");
        setBadge("crypto-badge", "SIN PAQUETE", "neutral");
        setText(
            "crypto-error",
            "El servidor aún no ha procesado tráfico cifrado."
        );
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

function drawLine(id, values) {
    const polyline = $(id);

    if (!Array.isArray(values) || values.length === 0) {
        polyline.setAttribute("points", "");
        return;
    }

    const numeric = values.map((value) => Number(value) || 0);
    const minValue = Math.min(...numeric);
    const maxValue = Math.max(...numeric);

    const x0 = 30;
    const x1 = 575;
    const yTop = 24;
    const yBottom = 160;

    const range = Math.max(maxValue - minValue, 1);
    const step = numeric.length === 1
        ? 0
        : (x1 - x0) / (numeric.length - 1);

    const points = numeric.map((value, index) => {
        const x = x0 + index * step;
        const ratio = (value - minValue) / range;
        const y = yBottom - ratio * (yBottom - yTop);

        return `${x.toFixed(1)},${y.toFixed(1)}`;
    });

    polyline.setAttribute("points", points.join(" "));
}


let lastAnimatedPacketCount = null;
let flowAnimationRunning = false;

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function resetFlowAnimation() {
    [
        "node-sensor",
        "node-esp32",
        "node-transport",
        "node-flask"
    ].forEach((id) => {
        const el = $(id);
        if (el) {
            el.classList.remove("flow-active", "flow-success", "flow-error");
        }
    });

    [
        "step-ecdh",
        "step-hkdf",
        "step-aes",
        "step-verify",
        "step-decrypt"
    ].forEach((id) => {
        const el = $(id);
        if (el) {
            el.classList.remove("step-active", "step-success");
        }
    });

    const channel = $("encrypted-channel");
    if (channel) channel.classList.remove("channel-active");

    const caption = $("flow-caption");
    if (caption) {
        caption.classList.remove("active", "success", "error");
        caption.textContent = "Esperando un nuevo paquete cifrado…";
    }
}

function activateStep(id, success = false) {
    const el = $(id);
    if (!el) return;

    el.classList.remove("step-active", "step-success");
    el.classList.add(success ? "step-success" : "step-active");
}

async function runEndToEndAnimation(isValid = true) {
    if (flowAnimationRunning) return;

    flowAnimationRunning = true;
    resetFlowAnimation();

    const caption = $("flow-caption");
    const sensor = $("node-sensor");
    const esp32 = $("node-esp32");
    const transport = $("node-transport");
    const flask = $("node-flask");
    const channel = $("encrypted-channel");

    try {
        // 1. Captura en origen
        sensor?.classList.add("flow-active");
        caption?.classList.add("active");
        if (caption) caption.textContent = "1/6 · Sensor MQ: lectura capturada en el origen";
        await sleep(420);

        // 2. ECDH
        sensor?.classList.remove("flow-active");
        esp32?.classList.add("flow-active");
        activateStep("step-ecdh");
        if (caption) caption.textContent = "2/6 · ESP32: establecimiento del secreto compartido mediante ECDH";
        await sleep(430);

        // 3. HKDF
        activateStep("step-ecdh", true);
        activateStep("step-hkdf");
        if (caption) caption.textContent = "3/6 · ESP32: derivación de clave con HKDF-SHA256";
        await sleep(430);

        // 4. AES-GCM
        activateStep("step-hkdf", true);
        activateStep("step-aes");
        if (caption) caption.textContent = "4/6 · ESP32: cifrado autenticado AES-256-GCM";
        await sleep(480);
        activateStep("step-aes", true);

        // 5. Tránsito cifrado
        esp32?.classList.remove("flow-active");
        transport?.classList.add("flow-active");
        channel?.classList.remove("channel-active");
        // reflow to allow replay of CSS animation
        void channel?.offsetWidth;
        channel?.classList.add("channel-active");
        if (caption) caption.textContent = "5/6 · Tránsito: ciphertext, nonce, tag y client_pub viajan protegidos";
        await sleep(1200);

        transport?.classList.remove("flow-active");
        flask?.classList.add(isValid ? "flow-active" : "flow-error");

        // 6. Verificación y descifrado
        activateStep("step-verify");
        if (caption) caption.textContent = "6/6 · Flask: validación de integridad mediante TAG AES-GCM";
        await sleep(420);

        if (isValid) {
            activateStep("step-verify", true);
            activateStep("step-decrypt");
            await sleep(420);
            activateStep("step-decrypt", true);

            flask?.classList.remove("flow-active");
            flask?.classList.add("flow-success");

            caption?.classList.remove("active");
            caption?.classList.add("success");
            if (caption) caption.textContent = "✓ Paquete autenticado y dato recuperado únicamente en el servidor";

            // Resaltar la tarjeta de dato recuperado.
            const recoveredCard = $("adc-value")?.closest(".metric-card");
            if (recoveredCard) {
                recoveredCard.classList.remove("data-arrived");
                void recoveredCard.offsetWidth;
                recoveredCard.classList.add("data-arrived");
            }
        } else {
            caption?.classList.remove("active");
            caption?.classList.add("error");
            if (caption) caption.textContent = "✕ Paquete rechazado: la autenticación AES-GCM no fue válida";
        }

        await sleep(1600);
    } finally {
        resetFlowAnimation();
        flowAnimationRunning = false;
    }
}

function maybeAnimateNewPacket(metrics) {
    const packetCount = Number(metrics.valid_packets ?? 0);

    // Evita animar datos históricos al abrir/recargar el dashboard.
    if (lastAnimatedPacketCount === null) {
        lastAnimatedPacketCount = packetCount;
        return;
    }

    if (packetCount > lastAnimatedPacketCount) {
        lastAnimatedPacketCount = packetCount;
        runEndToEndAnimation(true);
        return;
    }

    if (metrics.crypto_status === "RECHAZADO") {
        const rejectedCount = Number(metrics.rejected_packets ?? 0);
        const rejectionKey = `r:${rejectedCount}`;

        if (window.__lastRejectionAnimation !== rejectionKey) {
            window.__lastRejectionAnimation = rejectionKey;
            runEndToEndAnimation(false);
        }
    }
}


async function checkHealth() {
    try {
        const response = await fetch("/api/health", { cache: "no-store" });

        if (!response.ok) {
            throw new Error("health check failed");
        }

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

        if (!response.ok) {
            throw new Error("metrics request failed");
        }

        const data = await response.json();
        const metrics = data.metrics;

        updateServerState(true);
        updateDeviceState(metrics);
        updateCryptoStatus(metrics);
        updateSensorStatus(metrics.sensor_status);
        maybeAnimateNewPacket(metrics);

        setText("adc-value", metrics.adc ?? "—");

        setText(
            "voltage-value",
            metrics.voltage === null || metrics.voltage === undefined
                ? "—"
                : `${Number(metrics.voltage).toFixed(4)} V`
        );

        setText(
            "latency-value",
            `${Number(metrics.latency_ms ?? 0).toFixed(0)} ms`
        );

        setText(
            "memory-value",
            `${Number(metrics.free_heap_kb ?? 0).toFixed(2)} KB`
        );

        setText(
            "cpu-reference-value",
            `${Number(metrics.cpu_estimate_pct ?? 40).toFixed(2)} %`
        );

        setText(
            "crypto-time-value",
            `${Number(metrics.crypto_ms ?? 0).toFixed(0)} ms`
        );

        setText("ciphertext-value", metrics.raw_ciphertext || "-");
        setText("client-pub-value", metrics.client_pub_preview || "-");
        setText("nonce-value", metrics.nonce_preview || "-");
        setText("tag-value", metrics.tag_preview || "-");

        setText("valid-packets", metrics.valid_packets ?? 0);
        setText("rejected-packets", metrics.rejected_packets ?? 0);

        setText(
            "success-rate",
            `${Number(metrics.success_rate_pct ?? 0).toFixed(2)} %`
        );

        setText("last-update", formatTimestamp(metrics.last_update));

        setText(
            "latency-last",
            `${Number(metrics.latency_ms ?? 0).toFixed(0)} ms`
        );

        setText(
            "memory-last",
            `${Number(metrics.free_heap_kb ?? 0).toFixed(2)} KB`
        );

        drawLine("latency-line", data.history_latency);
        drawLine("memory-line", data.history_memory_kb);

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
