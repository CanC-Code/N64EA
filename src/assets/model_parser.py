import logging
import struct

logger = logging.getLogger(__name__)

class ModelParser:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.rom_data = analyzer.rom_data
        self.logger = logging.getLogger(__name__)
        self.logger.debug(f"Initializing ModelParser with ROM size: {len(self.rom_data)}")
        self.logger.debug("ModelParser initialized")

    def parse(self, offset, output_path=None):
        """Parse an F3D/F3DEX/F3DEX2 display list to a simple model."""
        try:
            self.logger.debug(f"Parsing model at offset 0x{offset:08x}")
            vertices = []
            triangles = []
            max_length = min(4096, len(self.rom_data) - offset)
            data = self.rom_data[offset:offset + max_length]
            i = 0
            while i < len(data) - 8:
                cmd = data[i]
                if cmd == 0xE7:  # G_NOP
                    i += 8
                    continue
                elif cmd == 0xB8:  # G_ENDDL
                    break
                elif cmd == 0x04:  # G_VTX
                    num_vertices = data[i + 1] >> 4
                    vtx_offset = int.from_bytes(data[i + 4:i + 8], 'big') & 0x7FFFFFFF
                    if vtx_offset + num_vertices * 16 > len(self.rom_data):
                        self.logger.warning(f"Invalid vertex offset 0x{vtx_offset:08x}")
                        i += 8
                        continue
                    vtx_data = self.rom_data[vtx_offset:vtx_offset + num_vertices * 16]
                    for j in range(0, len(vtx_data), 16):
                        x, y, z = struct.unpack('>hhh', vtx_data[j:j+6])
                        vertices.append((x / 1000.0, y / 1000.0, z / 1000.0))
                    i += 8
                elif cmd == 0x01:  # G_TRI1
                    v1 = data[i + 5] // 2
                    v2 = data[i + 6] // 2
                    v3 = data[i + 7] // 2
                    if max(v1, v2, v3) < len(vertices):
                        triangles.append((v1, v2, v3))
                    i += 8
                else:
                    i += 8
            model_data = {'vertices': vertices, 'triangles': triangles}
            if output_path:
                with open(output_path, 'w') as f:
                    for i, v in enumerate(vertices):
                        f.write(f"v {v[0]} {v[1]} {v[2]}\n")
                    for t in triangles:
                        f.write(f"f {t[0]+1} {t[1]+1} {t[2]+1}\n")
                self.logger.debug(f"Model saved to {output_path}")
            return model_data
        except Exception as e:
            self.logger.error(f"Failed to parse model at offset 0x{offset:08x}: {e}")
            raise
