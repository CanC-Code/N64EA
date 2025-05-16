import logging
from PIL import Image
import numpy as np

logger = logging.getLogger(__name__)

class ImageDecoder:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Initializing ImageDecoder")
        self.logger.debug("ImageDecoder initialized")

    def decode(self, asset, output_path, rom_data):
        """Decode an N64 texture to RGBA."""
        try:
            asset_type = asset['type']
            offset = asset['offset']
            width = asset.get('width', 64)
            height = asset.get('height', 32)
            self.logger.debug(f"Decoding {asset_type} at offset 0x{offset:08x}, {width}x{height}")

            if asset_type == 'texture_ci4':
                length = asset['length']
                palette_offset = asset.get('palette_offset', offset + length)
                if palette_offset + 32 > len(rom_data):
                    raise ValueError("Palette offset exceeds ROM size")
                data = rom_data[offset:offset + length]
                palette = rom_data[palette_offset:palette_offset + 32]
                palette_colors = []
                for i in range(0, 32, 2):
                    color = int.from_bytes(palette[i:i+2], 'big')
                    r = ((color >> 11) & 0x1F) << 3
                    g = ((color >> 6) & 0x1F) << 3
                    b = ((color >> 1) & 0x1F) << 3
                    a = 255 if (color & 1) else 0
                    palette_colors.append((r, g, b, a))
                pixels = np.zeros((height, width, 4), dtype=np.uint8)
                for y in range(height):
                    for x in range(width // 2):
                        pixel = data[(y * width // 2) + x]
                        idx1 = (pixel >> 4) & 0xF
                        idx2 = pixel & 0xF
                        pixels[y, x * 2] = palette_colors[idx1]
                        pixels[y, x * 2 + 1] = palette_colors[idx2]
                img = Image.fromarray(pixels, 'RGBA')
                if output_path:
                    img.save(output_path)
                return {'width': width, 'height': height, 'data': img.tobytes()}
            elif asset_type == 'texture_ci8':
                length = asset['length']
                palette_offset = asset.get('palette_offset', offset + length)
                if palette_offset + 512 > len(rom_data):
                    raise ValueError("Palette offset exceeds ROM size")
                data = rom_data[offset:offset + length]
                palette = rom_data[palette_offset:palette_offset + 512]
                palette_colors = []
                for i in range(0, 512, 2):
                    color = int.from_bytes(palette[i:i+2], 'big')
                    r = ((color >> 11) & 0x1F) << 3
                    g = ((color >> 6) & 0x1F) << 3
                    b = ((color >> 1) & 0x1F) << 3
                    a = 255 if (color & 1) else 0
                    palette_colors.append((r, g, b, a))
                pixels = np.zeros((height, width, 4), dtype=np.uint8)
                for y in range(height):
                    for x in range(width):
                        pixel = data[y * width + x]
                        pixels[y, x] = palette_colors[pixel]
                img = Image.fromarray(pixels, 'RGBA')
                if output_path:
                    img.save(output_path)
                return {'width': width, 'height': height, 'data': img.tobytes()}
            elif asset_type == 'texture_rgba16':
                length = asset['length']
                data = rom_data[offset:offset + length]
                pixels = np.zeros((height, width, 4), dtype=np.uint8)
                for y in range(height):
                    for x in range(width):
                        pixel = int.from_bytes(data[(y * width + x) * 2:(y * width + x) * 2 + 2], 'big')
                        r = ((pixel >> 11) & 0x1F) << 3
                        g = ((pixel >> 6) & 0x1F) << 3
                        b = ((pixel >> 1) & 0x1F) << 3
                        a = 255 if (pixel & 1) else 0
                        pixels[y, x] = (r, g, b, a)
                img = Image.fromarray(pixels, 'RGBA')
                if output_path:
                    img.save(output_path)
                return {'width': width, 'height': height, 'data': img.tobytes()}
            else:
                raise ValueError(f"Unsupported texture type: {asset_type}")
        except Exception as e:
            self.logger.error(f"Failed to decode image at offset 0x{offset:08x}: {e}")
            raise
