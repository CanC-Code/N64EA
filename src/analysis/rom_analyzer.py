import os
import logging
import yaml
import json
import mmap
import struct
from assets.image_decoder import ImageDecoder
from assets.model_parser import ModelParser
from assets.crc_calculator import CRCCalculator
from assets.decompressor import Decompressor
from analysis.splat_integration import SplatIntegration
from analysis.game_config import GAME_CONFIGS

logger = logging.getLogger(__name__)

class RomAnalyzer:
    def __init__(self, rom_path, output_dir):
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Starting RomAnalyzer initialization")
        self.rom_path = rom_path
        self.output_dir = output_dir
        self.image_folder = os.path.join(self.output_dir, 'images')
        self.audio_folder = os.path.join(self.output_dir, 'audio')
        self.compressed_folder = os.path.join(self.output_dir, 'compressed')
        self.segments_folder = os.path.join(self.output_dir, 'segments')
        self.other_folder = os.path.join(self.output_dir, 'other')
        self.temp_asset_file = os.path.join(self.output_dir, 'temp_assets.json')
        self.rom_data = None
        self.rom_file = None
        self.rom_mmap = None
        self.image_decoder = ImageDecoder()
        self.crc_calculator = CRCCalculator()
        self.decompressor = Decompressor()
        self.segments = []
        self.assets = []
        self.game_config = self.detect_game()
        self.load_rom()
        self.extract_info()
        self.model_parser = ModelParser(self)
        self.logger.debug("RomAnalyzer initialized")

    def detect_game(self):
        try:
            with open(self.rom_path, 'rb') as f:
                header = f.read(64)
            title = header[32:52].decode('ascii', errors='ignore').strip().lower()
            code = header[59:63].decode('ascii', errors='ignore').strip()
            for game, config in GAME_CONFIGS.items():
                if config['title'].lower() in title or config['code'] == code:
                    self.logger.info(f"Detected game: {game}")
                    return config
            self.logger.info("No specific game detected, using default configuration")
            return GAME_CONFIGS['default']
        except Exception as e:
            self.logger.error(f"Failed to detect game: {e}")
            return GAME_CONFIGS['default']

    def update_game_config(self, game_title, game_code, new_patterns):
        """Update game_config.py with new patterns for the detected game."""
        try:
            # Load existing game_config.py
            game_config_path = os.path.join(os.path.dirname(__file__), 'game_config.py')
            with open(game_config_path, 'r') as f:
                config_content = f.read()
            
            # Parse existing GAME_CONFIGS
            local_vars = {}
            exec(config_content, {}, local_vars)
            game_configs = local_vars.get('GAME_CONFIGS', {})

            # Update or create game entry
            if game_title not in game_configs:
                game_configs[game_title] = {
                    'title': game_title,
                    'code': game_code,
                    'rom_offset': 0x1000,
                    'splat_config': {
                        'base_address': 0x80000000,
                        'code_start': 0x80000400,
                        'data_start': 0x80200000
                    },
                    'patterns': []
                }
            
            # Add new patterns, avoiding duplicates
            existing_signatures = {p['signature'] for p in game_configs[game_title]['patterns']}
            for pattern in new_patterns:
                if pattern['signature'] not in existing_signatures:
                    game_configs[game_title]['patterns'].append(pattern)
                    self.logger.info(f"Added new pattern for {game_title}: {pattern['type']} at signature {pattern['signature']}")

            # Write updated GAME_CONFIGS back to game_config.py
            with open(game_config_path, 'w') as f:
                f.write("# Game-specific configurations for N64 ROM analysis\n")
                f.write("GAME_CONFIGS = {\n")
                for game, config in game_configs.items():
                    f.write(f"    \"{game}\": {{\n")
                    f.write(f"        \"title\": \"{config['title']}\",\n")
                    f.write(f"        \"code\": \"{config['code']}\",\n")
                    f.write(f"        \"rom_offset\": {config['rom_offset']},\n")
                    f.write(f"        \"splat_config\": {{\n")
                    for k, v in config['splat_config'].items():
                        f.write(f"            \"{k}\": {v},\n")
                    f.write(f"        }},\n")
                    f.write(f"        \"patterns\": [\n")
                    for pattern in config['patterns']:
                        f.write(f"            {{\n")
                        for k, v in pattern.items():
                            if isinstance(v, str) and k != 'signature':
                                f.write(f"                \"{k}\": \"{v}\",\n")
                            else:
                                f.write(f"                \"{k}\": {v},\n")
                        f.write(f"            }},\n")
                    f.write(f"        ]\n")
                    f.write(f"    }},\n")
                f.write("}\n")
            self.logger.info(f"Updated {game_config_path} with new patterns for {game_title}")
        except Exception as e:
            self.logger.error(f"Failed to update game_config.py: {e}")

    def load_rom(self):
        self.logger.debug("Entering load_rom")
        try:
            self.rom_file = open(self.rom_path, 'rb')
            self.rom_mmap = mmap.mmap(self.rom_file.fileno(), 0, access=mmap.ACCESS_READ)
            self.rom_data = self.rom_mmap
            self.logger.debug(f"ROM loaded (memory-mapped), size={len(self.rom_data)} bytes")
        except Exception as e:
            self.logger.error(f"Failed to load ROM: {e}")
            raise
        self.logger.debug("Exiting load_rom")

    def extract_info(self):
        self.logger.debug("Extracting ROM info")
        try:
            header = self.rom_data[:64]
            game_title = header[32:52].decode('ascii', errors='ignore').strip()
            game_code = header[59:63].decode('ascii', errors='ignore').strip()
            version = header[63]
            endian = 'big' if header[0] in [0x80, 0x37, 0x12] else 'little'
            self.logger.info(f"ROM Game Title: {game_title}, Code: {game_code}, Version: {version}, Endian: {endian}")
            self.rom_info = {
                'game_title': game_title,
                'game_code': game_code,
                'version': version,
                'endian': endian,
                'size': len(self.rom_data),
                'crc1': self.crc_calculator.calculate_crc(self.rom_data[0x10:0x14]),
                'crc2': self.crc_calculator.calculate_crc(self.rom_data[0x14:0x18])
            }
        except Exception as e:
            self.logger.error(f"Failed to extract ROM info: {e}")
            self.rom_info = {}

    def detect_offsets(self):
        self.logger.debug("Entering detect_offsets")
        try:
            splat = SplatIntegration(self.rom_path, self.output_dir)
            splat.run_splat(self)
            self.logger.debug(f"Splat config: segments={len(self.segments)}, assets={len(self.assets)}")
            if not self.assets:
                self._heuristic_asset_detection()
            self.save_temp_assets()
            self.save_rom_info()
            self.logger.debug(f"Detected {len(self.assets)} assets, {len(self.segments)} segments")
        except Exception as e:
            self.logger.error(f"Failed to detect offsets: {e}")
            self._heuristic_asset_detection()

    def _heuristic_asset_detection(self):
        self.logger.debug("Performing heuristic asset detection")
        rom_size = len(self.rom_data)
        new_patterns = []
        game_title = self.rom_info.get('game_title', 'Unknown')
        game_code = self.rom_info.get('game_code', 'XXXX')

        # Existing patterns from game_config
        for pattern in self.game_config['patterns']:
            pattern_type = pattern['type']
            signature = bytes.fromhex(pattern['signature'])
            length = pattern.get('length', 2048)
            step = pattern.get('step', 16)
            offset = 0x1000
            while offset < rom_size - len(signature):
                chunk = self.rom_data[offset:offset + len(signature)]
                if chunk == signature:
                    asset = {
                        'type': pattern_type,
                        'offset': offset,
                        'length': length
                    }
                    if pattern_type in ['texture_ci4', 'texture_ci8']:
                        asset.update({
                            'width': pattern.get('width', 64),
                            'height': pattern.get('height', 32),
                            'palette_offset': offset + length
                        })
                    elif pattern_type == 'texture_rgba16':
                        asset.update({
                            'width': pattern.get('width', 32),
                            'height': pattern.get('height', 32)
                        })
                    self.assets.append(asset)
                    self.segments.append([offset, offset + length, pattern_type])
                offset += step

        # Detect new patterns (e.g., by scanning for common signatures)
        candidate_signatures = {
            'texture_ci4': b'\x00\x00\x00\x00\x00\x00\x00\x00',
            'vadpcm': b'\x00\x00\x00\x00\x00\x00\x00\x00',
            'mio0': b'MIO0'
        }
        for pattern_type, signature in candidate_signatures.items():
            offset = 0x1000
            length = 2048 if pattern_type != 'mio0' else 4096
            step = 16
            while offset < rom_size - len(signature):
                chunk = self.rom_data[offset:offset + len(signature)]
                if chunk == signature:
                    new_pattern = {
                        'type': pattern_type,
                        'signature': signature.hex(),
                        'length': length,
                        'step': step
                    }
                    if pattern_type in ['texture_ci4', 'texture_ci8']:
                        new_pattern.update({
                            'width': 64,
                            'height': 32
                        })
                    elif pattern_type == 'texture_rgba16':
                        new_pattern.update({
                            'width': 32,
                            'height': 32
                        })
                    new_patterns.append(new_pattern)
                    asset = {
                        'type': pattern_type,
                        'offset': offset,
                        'length': length
                    }
                    self.assets.append(asset)
                    self.segments.append([offset, offset + length, pattern_type])
                offset += step

        # Update game_config.py with new patterns
        if new_patterns:
            self.update_game_config(game_title, game_code, new_patterns)

        self.logger.info(f"Added {len(self.assets)} heuristic assets in rom_analyzer")

    def extract_asset(self, asset, asset_types=None):
        if not asset_types:
            asset_types = {'textures', 'audio', 'compressed', 'models'}
        self.logger.debug(f"Extracting asset: {asset['type']} at 0x{asset['offset']:08x}")
        os.makedirs(self.image_folder, exist_ok=True)
        os.makedirs(self.audio_folder, exist_ok=True)
        os.makedirs(self.compressed_folder, exist_ok=True)
        os.makedirs(self.segments_folder, exist_ok=True)
        os.makedirs(self.other_folder, exist_ok=True)
        try:
            asset_type = asset['type']
            offset = asset['offset']
            output_path = None
            if asset_type in ['texture_ci4', 'texture_ci8', 'texture_rgba16'] and 'textures' in asset_types:
                output_path = os.path.join(self.image_folder, f"texture_0x{offset:08x}.png")
                self.image_decoder.decode(asset, output_path, self.rom_data)
            elif asset_type in ['mio0', 'yaz0'] and 'compressed' in asset_types:
                output_path = os.path.join(self.compressed_folder, f"{asset_type}_0x{offset:08x}.bin")
                decompressed_path = os.path.join(self.compressed_folder, f"{asset_type}_0x{offset:08x}_decompressed.bin")
                with open(output_path, 'wb') as f:
                    f.write(self.rom_data[offset:offset + asset['length']])
                self.decompressor.decompress(asset_type, output_path, decompressed_path)
            elif asset_type == 'vadpcm' and 'audio' in asset_types:
                output_path = os.path.join(self.audio_folder, f"vadpcm_0x{offset:08x}.bin")
                with open(output_path, 'wb') as f:
                    f.write(self.rom_data[offset:offset + asset['length']])
            elif asset_type == 'model' and 'models' in asset_types:
                output_path = os.path.join(self.segments_folder, f"model_0x{offset:08x}.obj")
                self.model_parser.parse(asset['offset'], output_path)
            else:
                output_path = os.path.join(self.other_folder, f"asset_0x{offset:08x}.bin")
                with open(output_path, 'wb') as f:
                    f.write(self.rom_data[offset:offset + asset['length']])
            if output_path:
                self.logger.debug(f"Extracted {asset_type} to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to extract asset at offset 0x{asset.get('offset', 0):08x}: {e}")

    def extract_assets(self, asset_types=None):
        for asset in self.assets:
            self.extract_asset(asset, asset_types)

    def compare_roms(self, compare_rom_path):
        try:
            with open(compare_rom_path, 'rb') as f:
                compare_mmap = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            if len(self.rom_data) != len(compare_mmap):
                compare_mmap.close()
                return {"error": "ROMs have different sizes"}
            differences = []
            for i in range(len(self.rom_data)):
                if self.rom_data[i] != compare_mmap[i]:
                    differences.append((i, self.rom_data[i], compare_mmap[i]))
            compare_mmap.close()
            return differences
        except Exception as e:
            self.logger.error(f"Failed to compare ROMs: {e}")
            return {"error": str(e)}

    def rebuild_rom(self, output_path):
        self.logger.debug(f"Rebuilding ROM to {output_path}")
        try:
            with open(output_path, 'wb') as f:
                f.write(self.rom_data)
            self.crc_calculator.update_crc(output_path)
            self.logger.info(f"Rebuilt ROM saved to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to rebuild ROM: {e}")
            raise

    def get_image_data(self, offset, format_type):
        for asset in self.assets:
            if asset['offset'] == offset and asset['type'] in ['texture_ci4', 'texture_ci8', 'texture_rgba16']:
                return self.image_decoder.decode(asset, None, self.rom_data)
        return None

    def get_model_data(self, offset):
        for asset in self.assets:
            if asset['offset'] == offset and asset['type'] == 'model':
                return self.model_parser.parse(asset['offset'])
        return None

    def save_temp_assets(self):
        self.logger.debug(f"Saving temp assets to {self.temp_asset_file}")
        try:
            with open(self.temp_asset_file, 'w') as f:
                json.dump(self.assets, f, indent=2)
            self.logger.debug(f"Saved {len(self.assets)} assets")
        except Exception as e:
            self.logger.error(f"Failed to save temp assets: {e}")

    def save_rom_info(self):
        self.logger.debug("Saving ROM info")
        try:
            with open(os.path.join(self.output_dir, 'rom_info.yaml'), 'w') as f:
                yaml.safe_dump(self.rom_info, f)
            self.logger.info(f"Saved ROM info to {os.path.join(self.output_dir, 'rom_info.yaml')}")
        except Exception as e:
            self.logger.error(f"Failed to save ROM info: {e}")

    def __del__(self):
        if self.rom_mmap is not None:
            self.rom_mmap.close()
        if self.rom_file is not None:
            self.rom_file.close()
