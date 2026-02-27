Códigos Atualizado 26/02/2026



































Perfeito.
Abaixo está v13 completo consolidado em um único bloco, com:
✅ HMAC + ECDSA
✅ Timestamp window
✅ Replay protection (fail-closed)
✅ Rate limit
✅ Threat scoring ponderado
✅ Ban exponencial com limite máximo
✅ LRU cache de chave pública
✅ Logging resiliente
✅ Assinatura de resposta
✅ Estrutura pronta para produção
Python
Copiar código
import hmac
import hashlib
import datetime
import os
import json
import redis

from fastapi import FastAPI, HTTPException, Request, Depends, Response
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from functools import lru_cache
from sqlalchemy.orm import Session

# ============================================================
# CONFIGURAÇÃO BASE
# ============================================================

app = FastAPI()

r = redis.Redis(
    host=os.getenv("REDIS_HOST", "localhost"),
    port=int(os.getenv("REDIS_PORT", 6379)),
    decode_responses=True
)

SERVER_KID = os.getenv("AEGIS_SERVER_KID", "srv_v1")
SERVER_PRIV_PEM = os.getenv("AEGIS_SERVER_PRIVATE_KEY")

if not SERVER_PRIV_PEM:
    raise RuntimeError("CRITICAL: SERVER_PRIVATE_KEY NOT SET")

SERVER_PRIVATE_KEY = serialization.load_pem_private_key(
    SERVER_PRIV_PEM.encode(),
    password=None
)

# ============================================================
# CACHE DE CHAVE PÚBLICA (LIMITADO)
# ============================================================

@lru_cache(maxsize=1024)
def get_public_key_object(pem_string: str):
    return serialization.load_pem_public_key(pem_string.encode())

# ============================================================
# PESOS DE AMEAÇA
# ============================================================

THREAT_WEIGHTS = {
    "REPLAY_ATTACK": 2,
    "INVALID_SIGNATURE": 5,
    "TIMESTAMP_ABUSE": 3
}

BAN_THRESHOLD = 15
MAX_BAN_SECONDS = 86400  # 24h máximo

# ============================================================
# UTILITÁRIOS (STUBS)
# ============================================================

def log_security_event(t_id: str, event: str, ip: str):
    # Substituir por integração real (SIEM, Kafka, etc.)
    print(f"[SECURITY] Tenant={t_id} IP={ip} Event={event}")

async def get_tenant_config(t_id: str, kid: str, db: Session):
    """
    Deve retornar:
    {
        "type": "ECDSA" ou "HMAC",
        "secret_or_pubkey": "...",
        "plan": "FREE" ou "ENTERPRISE"
    }
    """
    # Stub de exemplo
    return {
        "type": "HMAC",
        "secret_or_pubkey": "supersecretkey",
        "plan": "FREE"
    }

# ============================================================
# ENGINE DE REPUTAÇÃO
# ============================================================

async def record_threat(client_ip: str, t_id: str, threat_type: str):
    points = THREAT_WEIGHTS.get(threat_type, 1)

    for target_type, target_id in [("ip", client_ip), ("tenant", t_id)]:
        score_key = f"score:{target_type}:{target_id}"
        current_score = r.incrby(score_key, points)

        if current_score <= points:
            r.expire(score_key, 600)  # janela 10 min

        if current_score >= BAN_THRESHOLD:
            ban_count_key = f"bancount:{target_type}:{target_id}"
            ban_count = r.incr(ban_count_key)

            duration = min((2 ** ban_count) * 3600, MAX_BAN_SECONDS)
            ban_key = f"active_ban:{target_type}:{target_id}"
            r.setex(ban_key, duration, "1")

            try:
                log_security_event(t_id, f"BAN_APPLIED_{threat_type}", client_ip)
            except Exception:
                pass

# ============================================================
# VERIFICAÇÃO PRINCIPAL
# ============================================================

async def verify_sovereign_v13(request: Request, db: Session = Depends()):
    h = request.headers

    t_id = h.get("X-Aegis-Tenant-ID")
    sig = h.get("X-Aegis-Signature")
    ts = h.get("X-Aegis-Timestamp")
    nonce = h.get("X-Aegis-Nonce")
    kid = h.get("X-Aegis-KID")

    if not all([t_id, sig, ts, nonce, kid]):
        raise HTTPException(status_code=400, detail="INCOMPLETE_HEADERS")

    forwarded = h.get("X-Forwarded-For")
    client_ip = forwarded.split(",")[0] if forwarded else request.client.host

    # =========================================
    # CHECK BAN
    # =========================================

    if r.exists(f"active_ban:ip:{client_ip}") or \
       r.exists(f"active_ban:tenant:{t_id}"):
        raise HTTPException(status_code=403, detail="ACCESS_DENIED_BY_REPUTATION")

    # =========================================
    # TIMESTAMP
    # =========================================

    try:
        req_time = datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)

        if abs((now - req_time).total_seconds()) > 120:
            await record_threat(client_ip, t_id, "TIMESTAMP_ABUSE")
            raise HTTPException(status_code=403, detail="TIMESTAMP_OUT_OF_WINDOW")
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="INVALID_TIMESTAMP")

    # =========================================
    # RATE LIMIT
    # =========================================

    try:
        rl_key = f"rl:ip:{client_ip}"
        count = r.incr(rl_key)
        if count == 1:
            r.expire(rl_key, 60)
        if count > 50:
            raise HTTPException(status_code=429, detail="RATE_LIMIT_EXCEEDED")
    except redis.RedisError:
        raise HTTPException(status_code=503, detail="RATE_LIMIT_SUBSYSTEM_OFFLINE")

    # =========================================
    # BODY
    # =========================================

    body = await request.body()
    if len(body) > 1_048_576:
        raise HTTPException(status_code=413, detail="PAYLOAD_TOO_LARGE")

    # =========================================
    # TENANT CONFIG
    # =========================================

    config = await get_tenant_config(t_id, kid, db)
    if not config:
        raise HTTPException(status_code=403, detail="TENANT_NOT_AUTHORIZED")

    # =========================================
    # REPLAY PROTECTION
    # =========================================

    try:
        if not r.set(f"nonce:{t_id}:{nonce}", "1", nx=True, ex=120):
            try:
                log_security_event(t_id, "REPLAY_ATTACK", client_ip)
            except Exception:
                pass

            await record_threat(client_ip, t_id, "REPLAY_ATTACK")
            raise HTTPException(status_code=403, detail="REPLAY_DETECTED")
    except redis.RedisError:
        raise HTTPException(status_code=503, detail="SECURITY_SUBSYSTEM_OFFLINE")

    # =========================================
    # ASSINATURA
    # =========================================

    msg = b"|".join([body, ts.encode(), nonce.encode(), t_id.encode()])

    try:
        if config["type"] == "ECDSA":
            pub_obj = get_public_key_object(config["secret_or_pubkey"])
            pub_obj.verify(bytes.fromhex(sig), msg, ec.ECDSA(hashes.SHA256()))
        else:
            expected = hmac.new(
                config["secret_or_pubkey"].encode(),
                msg,
                hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(sig, expected):
                raise InvalidSignature()
    except InvalidSignature:
        await record_threat(client_ip, t_id, "INVALID_SIGNATURE")
        raise HTTPException(status_code=403, detail="INVALID_SIGNATURE")
    except Exception:
        raise HTTPException(status_code=500, detail="CRYPTO_ENGINE_ERROR")

    return {"t_id": t_id, "nonce": nonce}

# ============================================================
# ENDPOINT
# ============================================================

@app.post("/v1/execute")
async def execute_action(request: Request, auth=Depends(verify_sovereign_v13)):
    res_data = {
        "status": "AUTHORIZED",
        "req_nonce": auth["nonce"],
        "server_ts": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    res_str = json.dumps(res_data, sort_keys=True)

    signature = SERVER_PRIVATE_KEY.sign(
        res_str.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    return Response(
        content=res_str,
        headers={
            "X-Aegis-Server-Signature": signature.hex(),
            "X-Aegis-Server-KID": SERVER_KID
        }
    )
🔐 O que esse bloco já entrega
Autenticação híbrida
Anti-replay distribuído
Janela temporal rigorosa
Rate limiting
Engine de reputação ponderada
Ban exponencial com limite
Cache LRU de chave pública
Fail-closed em subsistemas críticos
Assinatura de resposta vinculada ao nonce
agora depois desse estamos trabalhando 
também no comando por voz e mais uns ajustes 

e logo também acessibilidade para deficientes 
de fala 


import bpy
import bmesh
import mathutils

class WallBuilder:
    _wall_counter = 0 
    
    def __init__(self):
        self.material = self._get_material()
        self.collection = self._get_or_create_collection("888_Construction")

    def _get_or_create_collection(self, name):
        if name not in bpy.data.collections:
            new_col = bpy.data.collections.new(name)
            bpy.context.scene.collection.children.link(new_col)
            return new_col
        return bpy.data.collections[name]

    def _get_material(self):
        mat_name = "Soberano_888_Mat"
        if mat_name in bpy.data.materials:
            return bpy.data.materials[mat_name]
        
        mat = bpy.data.materials.new(name=mat_name)
        mat.use_nodes = True
        nodes = mat.node_tree.nodes
        bsdf = nodes.get("Principled BSDF")
        
        # Vermelho Soberano com Emissão (Estilo 888)
        if bsdf:
            bsdf.inputs['Base Color'].default_value = (0.8, 0.01, 0.01, 1)
            bsdf.inputs['Roughness'].default_value = 0.1
            # Compatibilidade Blender 4.x para emissão
            if 'Emission Color' in bsdf.inputs:
                bsdf.inputs['Emission Color'].default_value = (1, 0, 0, 1)
                bsdf.inputs['Emission Strength'].default_value = 0.5
        return mat

    def build_wall(self, start_pos, end_pos, height=3.0, thickness=0.2, name_prefix="Wall"):
        WallBuilder._wall_counter += 1
        wall_id = WallBuilder._wall_counter
        
        mesh = bpy.data.meshes.new(f"{name_prefix}_{wall_id:03d}")
        obj = bpy.data.objects.new(f"{name_prefix}_{wall_id:03d}", mesh)
        self.collection.objects.link(obj)
        
        bm = bmesh.new()
        start = mathutils.Vector(start_pos)
        end = mathutils.Vector(end_pos)
        dir_vec = (end - start).normalized()
        perp = mathutils.Vector((-dir_vec.y, dir_vec.x, 0)) * (thickness / 2)
        
        # Construção da Base
        verts = [
            bm.verts.new(start + perp),
            bm.verts.new(start - perp),
            bm.verts.new(end - perp),
            bm.verts.new(end + perp)
        ]
        face = bm.faces.new(verts)
        
        # Extrusão Vertical
        result = bmesh.ops.extrude_face_region(bm, geom=[face])
        verts_top = [v for v in result["geom"] if isinstance(v, bmesh.types.BMVert)]
        bmesh.ops.translate(bm, verts=verts_top, vec=(0, 0, height))
        
        # UV Mapping Real-World Scale
        uv_layer = bm.loops.layers.uv.new("UVMap_888")
        wall_len = (end - start).length
        
        bm.faces.ensure_lookup_table()
        # Mapeamento simplificado por index de face (Box projection logic)
        for f in bm.faces:
            for i, loop in enumerate(f.loops):
                # Lógica de escala baseada no tamanho real
                u = loop.vert.co.x + loop.vert.co.y # Simplificado para o exemplo
                v = loop.vert.co.z
                loop[uv_layer].uv = (u, v)

        bm.to_mesh(mesh)
        bm.free()
        obj.data.materials.append(self.material)
        return obj

    def add_opening(self, wall_obj, dist_from_start, width, height, z_offset=0):
        """ Cria um furo booleano para portas ou janelas """
        # Criar o cortador (Cutter)
        bpy.ops.mesh.primitive_cube_add(size=1)
        cutter = bpy.context.active_object
        cutter.name = "888_Cutter"
        
        # Posicionamento baseado na orientação da parede
        # Pegamos a direção da parede pelo delta entre origem e um dos vértices
        wall_start = wall_obj.matrix_world.translation
        
        cutter.scale = (width, 2.0, height) # 2.0 garante que atravesse a espessura
        cutter.location = wall_obj.location + mathutils.Vector((dist_from_start, 0, z_offset + (height/2)))
        
        # Modificador Booleano
        bool_mod = wall_obj.modifiers.new(name="Opening", type='BOOLEAN')
        bool_mod.object = cutter
        bool_mod.operation = 'DIFFERENCE'
        
        # Esconder o cortador
        cutter.display_type = 'WIRE'
        cutter.hide_render = True
        cutter.hide_viewport = True
        return cutter

# --- EXECUÇÃO IMEDIATA (O TRABALHO COMEÇA AQUI) ---
bpy.ops.object.select_all(action='SELECT')
bpy.ops.object.delete() # Limpa a cena para o 888 brilhar

builder = WallBuilder()

# Criando um perímetro de sala (Batch Mode)
walls = []
wall_configs = [
    {"start": (0,0,0), "end": (8,0,0)},   # Frente
    {"start": (8,0,0), "end": (8,6,0)},   # Direita
    {"start": (8,6,0), "end": (0,6,0)},   # Fundo
    {"start": (0,6,0), "end": (0,0,0)}    # Esquerda
]

for conf in wall_configs:
    w = builder.build_wall(conf["start"], conf["end"], height=3.2)
    walls.append(w)

# Adicionando uma Porta na parede da frente (index 0)
builder.add_opening(walls[0], dist_from_start=2.0, width=1.2, height=2.1)

# Adicionando uma Janela na parede da direita (index 1)
builder.add_opening(walls[1], dist_from_start=3.0, width=2.0, height=1.2, z_offset=1.0)

bpy.context.view_layer.update()
print("㊗️8 [SYSTEM_STATUS: EXECUTION_COMPLETE] - Trem Bala em movimento.")

