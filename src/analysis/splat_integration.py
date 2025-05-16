import subprocess
import yaml
import os
import logging
import glob
import re
import struct
from analysis.game_config import GAME_CONFIGS

logger = logging.getLogger(__name__)

class SplatIntegration:
    def __init__(self, rom_path, output_folder):
        self.rom_path = rom_path
        self.output_folder = output_folder
        self.yaml_path = os.path.join(output_folder, "rom_config.yaml")
        self.splat_path = "splat"
        self.logger = logging.getLogger(__name__)
        self.rom_metadata = self.read_rom_header()
        self.segments = []
        self.assets = []
        self.game_config = self.detect_game()
        self.generate_yaml()

    def read_rom_header(self):
        try:
            with open(self.rom_path, 'rb') as f:
                header = f.read(64)
            return {
                'pi_status': header[0],
                'clock_rate': int.from_bytes(header[4:8], 'big'),
                'entry_point': int.from_bytes(header[8:12], 'big'),
                'release': int.from_bytes(header[12:16], 'big'),
                'crc1': int.from_bytes(header[16:20], 'big'),
                'crc2': int.from_bytes(header[20:24], 'big'),
                'game_title': header[32:52].decode('ascii', errors='ignore').strip(),
                'game_code': header[59:63].decode('ascii', errors='ignore').strip(),
                'version': header[63]
            }
        except Exception as e:
            self.logger.error(f"Failed to read ROM header: {e}")
            return {}

    def detect_game(self):
        title = self.rom_metadata.get('game_title', '').lower()
        code = self.rom_metadata.get('game_code', '')
        for game, config in GAME_CONFIGS.items():
            if config['title'].lower() in title or config['code'] == code:
                self.logger.info(f"Detected game: {game}")
                return config
        self.logger.info("No specific game detected, using default configuration")
        return GAME_CONFIGS['default']

    def validate_utf8(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                f.read()
            self.logger.debug(f"File {file_path} is valid UTF-8")
            return True
        except UnicodeDecodeError as e:
            self.logger.error(f"File {file_path} is not valid UTF-8: {e}")
            return False

    def generate_yaml(self, segments=None, assets=None):
        self.logger.debug(f"Generating rom_config.yaml at {self.yaml_path}")
        try:
            rom_size = os.path.getsize(self.rom_path)
        except Exception as e:
            self.logger.error(f"Failed to get ROM size: {e}")
            rom_size = 0

        default_segments = [
            {
                'start': 0,
                'type': 'header',
                'name': 'header'
            },
            {
                'start': 0x1000,
                'type': 'code',
                'name': 'code'
            }
        ]

        segments_yaml = default_segments
        if segments:
            sorted_segments = sorted(segments, key=lambda x: x[0])
            merged_segments = []
            for start, end, seg_type in sorted_segments:
                if not merged_segments or merged_segments[-1][1] < start:
                    merged_segments.append([start, end, seg_type])
                else:
                    merged_segments[-1][1] = max(merged_segments[-1][1], end)
            segments_yaml = [
                {
                    'start': start,
                    'type': seg_type,
                    'name': f'{seg_type}_{start:08x}'
                }
                for start, end, seg_type in merged_segments
            ]

        config = {
            'name': os.path.splitext(os.path.basename(self.rom_path))[0],
            'platform': 'n64',
            'endian': 'big',
            'baserom': self.rom_path,
            'target_path': self.rom_path,
            'base_path': self.output_folder,
            'segments': segments_yaml,
            'assets': assets or [],
            'options': {
                'platform': 'n64',
                'endian': 'big',
                'target_isa': 'mips',
                'find_file_boundaries': True,
                'create_undefined_funcs_auto': True,
                'create_undefined_syms_auto': True
            }
        }

        try:
            with open(self.yaml_path, 'w', encoding='utf-8') as f:
                yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False)
            if not self.validate_utf8(self.yaml_path):
                raise RuntimeError("Invalid rom_config.yaml generated")
            self.logger.debug(f"Successfully wrote rom_config.yaml with {len(config['segments'])} segments, {len(config.get('assets', []))} assets")
        except Exception as e:
            self.logger.error(f"Failed to write or validate rom_config.yaml: {e}")
            raise

    def run_splat(self, analyzer):
        self.logger.debug("Entering run_splat")
        try:
            result = subprocess.run(["which", self.splat_path], capture_output=True, text=True, timeout=10)
            if not result.stdout.strip():
                self.logger.error("splat command not found in PATH")
                raise RuntimeError("splat command not found")
            self.segments = analyzer.segments or [[0, 0x1000, 'header'], [0x1000, os.path.getsize(self.rom_path), 'code']]
            self.assets = analyzer.assets or []
            self.generate_yaml(self.segments, self.assets)
            cmd = [self.splat_path, "split", self.yaml_path]
            self.logger.debug(f"Running splat: {' '.join(cmd)}")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
                self.logger.info("Splat completed successfully")
                self.logger.debug(f"Splat stdout: {result.stdout}")
                self.logger.debug(f"Splat stderr: {result.stderr}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Splat command failed with exit code {e.returncode}: {e.stderr}")
                raise
            except subprocess.TimeoutExpired as e:
                self.logger.error(f"Splat command timed out after {e.timeout} seconds")
                raise
            self.parse_splat_output(analyzer)
            analyzer.assets = self.assets
            analyzer.segments = self.segments
            self.update_segments_and_assets(self.segments, self.assets)
        except Exception as e:
            self.logger.error(f"Error running splat: {e}", exc_info=True)
            self._fallback(analyzer)

    def parse_splat_output(self, analyzer):
        self.logger.debug("Parsing n64splat output")
        asset_path = os.path.join(self.output_folder, 'assets')
        self.assets = []
        self.segments = [[0, 0x1000, 'header']]
        try:
            rom_size = os.path.getsize(self.rom_path)
            for root, _, files in os.walk(asset_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, self.output_folder)
                    offset = self._guess_asset_offset(rel_path)
                    if offset >= rom_size:
                        self.logger.warning(f"Invalid offset 0x{offset:x} for file {file_path}, skipping")
                        continue
                    if file.endswith('.png'):
                        self.assets.append({
                            'type': 'texture_ci4',
                            'offset': offset,
                            'length': 2048,
                            'width': 64,
                            'height': 32,
                            'palette_offset': offset + 2048
                        })
                        self.segments.append([offset, offset + 2048 + 32, 'texture_ci4'])
                    elif file.endswith('.bin') and 'mio0' in rel_path.lower():
                        length = os.path.getsize(file_path)
                        if offset + length <= rom_size:
                            self.assets.append({
                                'type': 'mio0',
                                'offset': offset,
                                'length': length
                            })
                            self.segments.append([offset, offset + length, 'mio0'])
                    elif file.endswith('.bin') and 'vadpcm' in rel_path.lower():
                        length = os.path.getsize(file_path)
                        if offset + length <= rom_size:
                            self.assets.append({
                                'type': 'vadpcm',
                                'offset': offset,
                                'length': length
                            })
                            self.segments.append([offset, offset + length, 'vadpcm'])
                    elif file.endswith('.obj'):
                        self.assets.append({
                            'type': 'model',
                            'offset': offset,
                            'length': 4096
                        })
                        self.segments.append([offset, offset + 4096, 'model'])
            self.logger.info(f"Parsed {len(self.assets)} assets from n64splat output")
            if not self.assets:
                self._add_heuristic_assets(analyzer, rom_size)
        except Exception as e:
            self.logger.error(f"Failed to parse splat output: {e}")
        self.segments.append([0x1000, rom_size, 'code'])
        self.segments = self.merge_segments(self.segments)

    def _add_heuristic_assets(self, analyzer, rom_size):
        self.logger.debug("Adding heuristic assets")
        try:
            with open(self.rom_path, 'rb') as f:
                rom_data = f.read(0x100000)  # Read only first 1MB to reduce memory usage
            for pattern in self.game_config['patterns']:
                pattern_type = pattern['type']
                signature = bytes.fromhex(pattern['signature'])
                length = pattern.get('length', 2048)
                step = pattern.get('step', 16)
                for offset in range(0x1000, rom_size - length, step):
                    if offset + len(signature) > len(rom_data):
                        with open(self.rom_path, 'rb') as f:
                            f.seek(offset)
                            chunk = f.read(len(signature))
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
            self.logger.info(f"Added {len(self.assets)} heuristic assets")
        except Exception as e:
            self.logger.error(f"Failed to add heuristic assets: {e}")

    def _guess_asset_offset(self, rel_path):
        match = re.search(r'0x([0-9a-fA-F]+)', rel_path)
        return int(match.group(1), 16) if match else 0

    def merge_segments(self, segments):
        if not segments:
            return []
        segments = sorted(segments, key=lambda x: x[0])
        merged = []
        current_start, current_end, current_type = segments[0]
        for start, end, seg_type in segments[1:]:
            if start <= current_end:
                current_end = max(current_end, end)
                current_type = seg_type if seg_type != 'code' else current_type
            else:
                merged.append([current_start, current_end, current_type])
                current_start, current_end, current_type = start, end, seg_type
        merged.append([current_start, current_end, current_type])
        return merged

    def _fallback(self, analyzer):
        self.logger.info("Falling back to heuristic segments")
        rom_size = os.path.getsize(self.rom_path)
        self.segments = [[0, 0x1000, 'header'], [0x1000, rom_size, 'code']]
        self.assets = []
        self._add_heuristic_assets(analyzer, rom_size)
        self.generate_yaml(self.segments, self.assets)

    def update_segments_and_assets(self, segments, assets):
        self.segments = segments
        self.assets = assets
        self.generate_yaml(segments, assets)
