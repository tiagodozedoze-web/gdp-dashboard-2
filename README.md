Códigos Atualizado 26/02/2026
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

