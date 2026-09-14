import base64
import os
import sys
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from flask import Flask, jsonify, render_template, request
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC


BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # 16 KB por solicitud

# Local: usa clave_privada.pem en la misma carpeta.
# Render: luego configuraremos PRIVATE_KEY_PATH hacia el Secret File.
PRIVATE_KEY_PATH = Path(
    os.getenv("PRIVATE_KEY_PATH", str(BASE_DIR / "clave_privada.pem"))
)

STATE_LOCK = Lock()

ULTIMAS_METRICAS = {
    "raw_ciphertext": "-",
    "adc": None,
    "voltage": None,
    "sensor_status": "SIN_DATOS",
    "decrypted_message": "-",
    "latency": 0,
    "esp_cpu": 0.0,
    "crypto_status": "ESPERANDO",
    "last_update": None,
    "packet_count": 0,
    "client_pub_preview": "-",
    "nonce_preview": "-",
    "tag_preview": "-",
    "last_error": None,
}

HISTORIAL_LATENCIA = deque(maxlen=20)
HISTORIAL_CPU = deque(maxlen=20)


def load_server_private_key():
    if not PRIVATE_KEY_PATH.exists():
        raise FileNotFoundError(
            f"No se encontró la clave privada del servidor en: {PRIVATE_KEY_PATH}"
        )

    pem = PRIVATE_KEY_PATH.read_text(encoding="utf-8")
    key = ECC.import_key(pem)

    if key.curve not in ("NIST P-256", "P-256"):
        print(
            f"[WARN] Curva privada: {key.curve} (esperada P-256)",
            file=sys.stderr,
        )

    return key


server_private_key = load_server_private_key()


def _sanitize_client_pub(raw: bytes) -> bytes:
    length = len(raw)

    if length == 64:
        return raw

    if length == 65 and raw[0] == 0x04:
        return raw[1:65]

    if length == 66:
        if raw[1] == 0x04:
            return raw[2:66]
        return raw[-64:]

    raise ValueError(f"Longitud de clave pública cliente inválida: {length} bytes")


def parse_client_pub(client_pub_bytes: bytes):
    xy = _sanitize_client_pub(client_pub_bytes)

    if len(xy) != 64:
        raise ValueError("La clave pública normalizada no contiene 64 bytes")

    x = int.from_bytes(xy[0:32], "big")
    y = int.from_bytes(xy[32:64], "big")

    return ECC.EccPoint(x=x, y=y, curve="P-256")


def derive_shared_key(client_pub_bytes: bytes):
    client_point = parse_client_pub(client_pub_bytes)
    shared_point = server_private_key.d * client_point
    x_bytes = int(shared_point.x).to_bytes(32, "big")

    return HKDF(
        master=x_bytes,
        key_len=32,
        salt=None,
        hashmod=SHA256,
        context=b"ECC_shared_key",
    )


def decrypt_aes_gcm(key, nonce, tag, ciphertext):
    if len(nonce) != 12:
        raise ValueError("Nonce AES-GCM inválido")

    if len(tag) != 16:
        raise ValueError("Tag AES-GCM inválido")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def decode_b64_field(data, field_name):
    value = data.get(field_name)

    if not isinstance(value, str) or not value:
        raise ValueError(f"Campo requerido ausente: {field_name}")

    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError(f"Base64 inválido en {field_name}") from exc


def parse_sensor_message(message: str):
    """
    Formato actual esperado del ESP32:
        mq_adc=1234,mq_v=1.2345

    Si el mensaje cambia, se conserva el texto descifrado y el dashboard
    seguirá funcionando.
    """
    result = {
        "adc": None,
        "voltage": None,
        "sensor_status": "DATO_RECIBIDO",
    }

    try:
        parts = {}
        for item in message.split(","):
            if "=" in item:
                key, value = item.split("=", 1)
                parts[key.strip()] = value.strip()

        adc = int(parts["mq_adc"])
        voltage = float(parts["mq_v"])

        if voltage < 1.0:
            sensor_status = "NORMAL"
        elif voltage <= 1.8:
            sensor_status = "ALERTA"
        else:
            sensor_status = "CRITICO"

        result.update(
            {
                "adc": adc,
                "voltage": round(voltage, 4),
                "sensor_status": sensor_status,
            }
        )
    except (KeyError, TypeError, ValueError):
        pass

    return result


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return response


@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "IoT Hybrid Crypto Server",
            "curve": "P-256",
            "kdf": "HKDF-SHA256",
            "cipher": "AES-256-GCM",
            "private_key_loaded": True,
        }
    )


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    with STATE_LOCK:
        snapshot = dict(ULTIMAS_METRICAS)
        latency_history = list(HISTORIAL_LATENCIA)
        cpu_history = list(HISTORIAL_CPU)

    return jsonify(
        {
            "metrics": snapshot,
            "history_latency": latency_history,
            "history_cpu": cpu_history,
            "crypto": {
                "key_exchange": "ECDH P-256",
                "derivation": "HKDF-SHA256",
                "encryption": "AES-256-GCM",
            },
        }
    )


@app.route("/data", methods=["POST"])
def receive_data():
    try:
        if not request.is_json:
            raise ValueError("La solicitud debe usar Content-Type application/json")

        data = request.get_json(silent=True)

        if not isinstance(data, dict):
            raise ValueError("JSON inválido")

        raw_b64_ciphertext = data.get("ciphertext")
        ciphertext = decode_b64_field(data, "ciphertext")
        nonce = decode_b64_field(data, "nonce")
        tag = decode_b64_field(data, "tag")
        client_pub = decode_b64_field(data, "client_pub")

        if not ciphertext:
            raise ValueError("Ciphertext vacío")

        key = derive_shared_key(client_pub)
        plaintext = decrypt_aes_gcm(key, nonce, tag, ciphertext)
        decrypted_message = plaintext.decode("utf-8", errors="replace")

        parsed = parse_sensor_message(decrypted_message)

        latency = safe_int(data.get("latency"), 0)
        esp_cpu = safe_float(data.get("esp_cpu"), 0.0)

        now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        with STATE_LOCK:
            ULTIMAS_METRICAS["raw_ciphertext"] = raw_b64_ciphertext
            ULTIMAS_METRICAS["decrypted_message"] = decrypted_message
            ULTIMAS_METRICAS["adc"] = parsed["adc"]
            ULTIMAS_METRICAS["voltage"] = parsed["voltage"]
            ULTIMAS_METRICAS["sensor_status"] = parsed["sensor_status"]
            ULTIMAS_METRICAS["latency"] = latency
            ULTIMAS_METRICAS["esp_cpu"] = round(esp_cpu, 2)
            ULTIMAS_METRICAS["crypto_status"] = "VALIDO"
            ULTIMAS_METRICAS["last_update"] = now
            ULTIMAS_METRICAS["packet_count"] += 1
            ULTIMAS_METRICAS["client_pub_preview"] = (
                base64.b64encode(client_pub).decode("ascii")[:42] + "..."
            )
            ULTIMAS_METRICAS["nonce_preview"] = (
                base64.b64encode(nonce).decode("ascii")
            )
            ULTIMAS_METRICAS["tag_preview"] = (
                base64.b64encode(tag).decode("ascii")
            )
            ULTIMAS_METRICAS["last_error"] = None

            HISTORIAL_LATENCIA.append(latency)
            HISTORIAL_CPU.append(round(esp_cpu, 2))

        print(
            f"[Cripto API] OK | {decrypted_message} | "
            f"latencia={latency} ms | cpu={esp_cpu:.2f}%"
        )
        sys.stdout.flush()

        return jsonify({"status": "OK"}), 200

    except Exception as exc:
        print(f"[Cripto API] Error: {exc}", file=sys.stderr)
        sys.stderr.flush()

        with STATE_LOCK:
            ULTIMAS_METRICAS["crypto_status"] = "RECHAZADO"
            ULTIMAS_METRICAS["last_error"] = (
                "Paquete rechazado: formato inválido o autenticación AES-GCM fallida"
            )

        return (
            jsonify(
                {
                    "status": "FAIL",
                    "error": "Paquete inválido o autenticación criptográfica fallida",
                }
            ),
            400,
        )


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
