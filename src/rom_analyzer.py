# N64EA
# Copyright (c) 2025 CanC-Code
# Licensed under the MIT License. See LICENSE file in the project root.

import struct
import yaml
import os
import logging
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor
from n64img.image import CI4, CI8
from datetime import datetime
import psutil
import time
import gc

# Configure logging with timestamps
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class RomAnalyzer:
    def __init__(self):
        self.rom_size = 0
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Initialized RomAnalyzer")

    def get_memory_usage(self):
        process = psutil.Process()
        mem_info = process.memory_info()
        return mem_info.rss / 1024 / 1024  # MB

    def get_cpu_usage(self):
        process = psutil.Process()
        return process.cpu_percent(interval=0.1)

    def check_resources(self):
        mem_usage = self.get_memory_usage()
        total_mem = psutil.virtual_memory().total / 1024 / 1024
        cpu_usage = self.get_cpu_usage()
        if mem_usage / total_mem > 0.8 or cpu_usage > 90:
            self.logger.warning(f"High resource usage: Memory={mem_usage:.2f}/{total_mem:.2f} MB, CPU={cpu_usage:.1f}%")
            time.sleep(2)  # Throttle to reduce load
            return False
        return True

    def load_rom(self, path):
        self.logger.debug(f"Entering load_rom: {path}")
        if not os.path.exists(path):
            self.logger.error(f"ROM file not found: {path}")
            raise FileNotFoundError(f"ROM file not found: {path}")
        try:
            with open(path, 'rb') as f:
                rom = bytearray(f.read())
            self.rom_size = len(rom)
            if self.rom_size < 0x1000:
                self.logger.error(f"ROM too small: 0x{self.rom_size:08x} bytes")
                raise ValueError(f"ROM too small: 0x{self.rom_size:08x} bytes")
            self.logger.info(f"ROM size: 0x{self.rom_size:08x} bytes")
            self.logger.debug(f"Memory usage: {self.get_memory_usage():.2f} MB")
            return rom
        except Exception as e:
            self.logger.error(f"Failed to load ROM: {str(e)}")
            raise
        finally:
            self.logger.debug("Exiting load_rom")

    def is_v64(self, rom):
        self.logger.debug("Entering is_v64")
        is_v64 = len(rom) >= 4 and rom[0:4] == b'\x37\x80\x40\x12'
        self.logger.info(f"ROM is {'V64' if is_v64 else 'Z64'}")
        self.logger.debug("Exiting is_v64")
        return is_v64

    def to_big_endian(self, rom):
        self.logger.debug("Entering to_big_endian")
        try:
            out = bytearray(len(rom))
            for i in range(0, len(rom), 2):
                out[i] = rom[i + 1]
                out[i + 1] = rom[i]
            self.logger.info("Converted ROM to big-endian")
            self.logger.debug(f"Memory usage: {self.get_memory_usage():.2f} MB")
            return out
        except Exception as e:
            self.logger.error(f"Failed to convert ROM to big-endian: {str(e)}")
            raise
        finally:
            self.logger.debug("Exiting to_big_endian")

    def decompress_mio0(self, rom, offset, length):
        self.logger.debug(f"Entering decompress_mio0: offset=0x{offset:08x}, length=0x{length:08x}")
        try:
            if offset + 16 > len(rom):
                self.logger.error(f"Invalid MIO0 offset: 0x{offset:08x}")
                return b''
            if rom[offset:offset+4] != b'\x11\x72\x00\x00':
                self.logger.error(f"No MIO0 header at 0x{offset:08x}")
                return b''
            comp_size = struct.unpack('>I', rom[offset+8:offset+12])[0]
            uncomp_size = struct.unpack('>I', rom[offset+12:offset+16])[0]
            if comp_size > len(rom) - offset or uncomp_size > 0x200000 or comp_size < 4:
                self.logger.error(f"Invalid MIO0 sizes: comp=0x{comp_size:08x}, uncomp=0x{uncomp_size:08x}")
                return b''
            output = bytearray(uncomp_size)
            comp_data = rom[offset+16:offset+16+comp_size]
            out_pos = 0
            comp_pos = 0
            while out_pos < uncomp_size and comp_pos < len(comp_data):
                control = comp_data[comp_pos]
                comp_pos += 1
                for bit in range(7, -1, -1):
                    if out_pos >= uncomp_size:
                        break
                    if (control >> bit) & 1:
                        if comp_pos < len(comp_data):
                            output[out_pos] = comp_data[comp_pos]
                            comp_pos += 1
                            out_pos += 1
                    else:
                        if comp_pos + 1 < len(comp_data):
                            backref = (comp_data[comp_pos] << 8) | comp_data[comp_pos+1]
                            comp_pos += 2
                            length = (backref >> 12) + 3
                            dist = (backref & 0xFFF) + 1
                            for _ in range(length):
                                if out_pos >= uncomp_size:
                                    break
                                if out_pos - dist >= 0:
                                    output[out_pos] = output[out_pos - dist]
                                out_pos += 1
            if out_pos < uncomp_size // 2:
                self.logger.error(f"MIO0 decompression failed: output too small (0x{out_pos:08x}/0x{uncomp_size:08x})")
                return b''
            self.logger.info(f"Decompressed MIO0 at 0x{offset:08x}, size=0x{out_pos:08x}")
            return bytes(output)
        except Exception as e:
            self.logger.error(f"Failed to decompress MIO0 at 0x{offset:08x}: {str(e)}")
            return b''
        finally:
            self.logger.debug("Exiting decompress_mio0")

    def find_mio0_headers(self, rom, progress_callback=None):
        self.logger.debug("Entering find_mio0_headers")
        potential_count = 0
        invalid_count = 0
        i = 0
        try:
            while i < len(rom) - 16:
                if not self.check_resources():
                    self.logger.warning("Throttling MIO0 scan due to high resource usage")
                if progress_callback and i % 0x100000 == 0:
                    progress_callback(i / (len(rom) - 16) * 20, f"Scanning MIO0: {potential_count} potential")
                idx = rom.find(b'\x11\x72\x00\x00', i)
                if idx == -1 or idx + 16 > len(rom):
                    break
                i = idx
                comp_size = struct.unpack('>I', rom[i+8:i+12])[0]
                uncomp_size = struct.unpack('>I', rom[i+12:i+16])[0]
                if potential_count < 10:
                    self.logger.info(f"Potential MIO0 at 0x{i:08x}, comp_size=0x{comp_size:08x}, uncomp_size=0x{uncomp_size:08x}")
                potential_count += 1
                if (4 <= comp_size <= 0x100000 and
                    4 <= uncomp_size <= 0x200000 and
                    uncomp_size >= comp_size and
                    i + comp_size <= len(rom)):
                    decomp_data = self.decompress_mio0(rom, i, comp_size)
                    if decomp_data:
                        yield {'offset': i, 'length': comp_size, 'type': 'mio0', 'uncomp_size': uncomp_size}
                        self.logger.info(f"Valid MIO0 at offset 0x{i:08x}")
                    else:
                        invalid_count += 1
                else:
                    if invalid_count < 10:
                        self.logger.warning(f"Invalid MIO0 at 0x{i:08x}: comp_size or uncomp_size out of range")
                    invalid_count += 1
                i += 4
            if invalid_count > 10:
                self.logger.info(f"Skipped {invalid_count - 10} additional invalid MIO0 headers")
        except Exception as e:
            self.logger.error(f"MIO0 scanning failed: {str(e)}")
        self.logger.info(f"Scanned {potential_count} potential MIO0 headers, {invalid_count} invalid")
        self.logger.debug(f"Memory usage: {self.get_memory_usage():.2f} MB")
        self.logger.debug("Exiting find_mio0_headers")

    def find_yaz0_headers(self, rom, progress_callback=None):
        self.logger.debug("Entering find_yaz0_headers")
        potential_count = 0
        invalid_count = 0
        i = 0
        try:
            while i < len(rom) - 16:
                if not self.check_resources():
                    self.logger.warning("Throttling Yaz0 scan due to high resource usage")
                if progress_callback and i % 0x100000 == 0:
                    progress_callback(20 + (i / (len(rom) - 16)) * 20, f"Scanning Yaz0: {potential_count} potential")
                idx = rom.find(b'\x59\x61\x7A\x30', i)
                if idx == -1 or idx + 8 > len(rom):
                    break
                i = idx
                uncomp_size = struct.unpack('>I', rom[i+4:i+8])[0]
                if potential_count < 10:
                    self.logger.info(f"Potential Yaz0 at 0x{i:08x}, uncomp_size=0x{uncomp_size:08x}")
                potential_count += 1
                if 4 <= uncomp_size <= 0x200000:
                    yield {'offset': i, 'length': 0, 'type': 'yaz0', 'uncomp_size': uncomp_size}
                    self.logger.info(f"Valid Yaz0 at offset 0x{i:08x}")
                else:
                    if invalid_count < 10:
                        self.logger.warning(f"Invalid Yaz0 at 0x{i:08x}: uncomp_size out of range")
                    invalid_count += 1
                i += 4
            if invalid_count > 10:
                self.logger.info(f"Skipped {invalid_count - 10} additional invalid Yaz0 headers")
        except Exception as e:
            self.logger.error(f"Yaz0 scanning failed: {str(e)}")
        self.logger.info(f"Scanned {potential_count} potential Yaz0 headers, {invalid_count} invalid")
        self.logger.debug(f"Memory usage: {self.get_memory_usage():.2f} MB")
        self.logger.debug("Exiting find_yaz0_headers")

    def find_textures(self, rom, progress_callback=None):
        self.logger.debug("Entering find_textures")
        chunk_size = 0x80000  # 512KB chunks
        try:
            for chunk_start in range(0, len(rom) - 0x1000, chunk_size):
                if not self.check_resources():
                    self.logger.warning("Throttling texture scan due to high resource usage")
                chunk_end = min(chunk_start + chunk_size, len(rom) - 0x1000)
                i = chunk_start
                texture_count = 0
                while i < chunk_end:
                    if progress_callback and i % 0x100000 == 0:
                        progress_callback(40 + (i / (len(rom) - 0x1000) * 30), f"Scanning Textures: {texture_count} textures")
                    for fmt, cls in [('ci4', CI4), ('ci8', CI8)]:
                        try:
                            img = cls(rom[i:i+0x1000], 32, 32)
                            yield {'offset': i, 'length': img.size, 'type': f'texture_{fmt}', 'uncomp_size': img.size}
                            self.logger.info(f"Found texture ({fmt}) at offset 0x{i:08x}, size 0x{img.size:08x}")
                            i += img.size
                            texture_count += 1
                            break
                        except:
                            i += 128  # Large skip for failed attempts
                            break
                self.logger.debug(f"Texture chunk 0x{chunk_start:08x}-0x{chunk_end:08x}, found {texture_count} textures, memory usage: {self.get_memory_usage():.2f} MB")
                gc.collect()  # Free memory after chunk
        except Exception as e:
            self.logger.error(f"Texture scanning failed: {str(e)}")
        self.logger.debug(f"Memory usage: {self.get_memory_usage():.2f} MB")
        self.logger.debug("Exiting find_textures")

    def extract_texture(self, rom, offset, length, fmt, output_dir):
        self.logger.debug(f"Entering extract_texture: offset=0x{offset:08x}, fmt={fmt}")
        try:
            img_class = {'ci4': CI4, 'ci8': CI8}[fmt]
            img = img_class(rom[offset:offset+length], 32, 32)
            texture_dir = os.path.join(output_dir, 'textures')
            os.makedirs(texture_dir, exist_ok=True)
            output_path = os.path.join(texture_dir, f'texture_0x{offset:08x}.png')
            img.write(output_path)
            self.logger.info(f"Saved texture to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to extract texture at 0x{offset:08x}: {str(e)}")
        finally:
            self.logger.debug("Exiting extract_texture")

    def find_audio(self, rom, progress_callback=None):
        self.logger.debug("Entering find_audio")
        potential_count = {'ctl': 0, 'seq': 0, 'tbl': 0, 'vadpcm': 0}
        invalid_count = {'ctl': 0, 'seq': 0, 'tbl': 0, 'vadpcm': 0}
        start_offset = int(self.rom_size * 0.75)  # Last 25% of ROM
        i = start_offset
        try:
            while i < len(rom) - 16:
                if not self.check_resources():
                    self.logger.warning("Throttling audio scan due to high resource usage")
                if progress_callback and i % 0x100000 == 0:
                    progress_callback(70 + ((i - start_offset) / (len(rom) - start_offset - 16) * 20),
                                     f"Scanning Audio: CTL={potential_count['ctl']}, SEQ={potential_count['seq']}, TBL={potential_count['tbl']}, VADPCM={potential_count['vadpcm']}")
                if rom[i:i+4] in [b'\x42\x4E\x4B\x20', b'\x53\x45\x51\x20']:
                    asset_type = 'ctl' if rom[i:i+4] == b'\x42\x4E\x4B\x20' else 'seq'
                    if potential_count[asset_type] < 10:
                        self.logger.info(f"Potential {asset_type.upper()} at 0x{i:08x}")
                    potential_count[asset_type] += 1
                    length = 0
                    if asset_type == 'seq' and i + 8 <= len(rom):
                        length = struct.unpack('>I', rom[i+4:i+8])[0]
                        if length > len(rom) - i or length > 0x100000:
                            if invalid_count[asset_type] < 10:
                                self.logger.warning(f"Invalid SEQ length at 0x{i:08x}: 0x{length:08x}")
                            invalid_count[asset_type] += 1
                            length = 0
                    elif asset_type == 'ctl' and i + 16 <= len(rom):
                        tbl_offset = struct.unpack('>I', rom[i+12:i+16])[0]
                        if 0 < tbl_offset < len(rom):
                            yield {'offset': tbl_offset, 'length': 0, 'type': 'tbl', 'uncomp_size': 0}
                            if potential_count['tbl'] < 10:
                                self.logger.info(f"Found TBL at offset 0x{tbl_offset:08x}")
                            potential_count['tbl'] += 1
                    yield {'offset': i, 'length': length, 'type': asset_type, 'uncomp_size': length}
                    self.logger.info(f"Found {asset_type.upper()} at offset 0x{i:08x}, length=0x{length:08x}")
                    i += 4
                elif i + 9 <= len(rom) and rom[i] & 0xF0 == 0x00:
                    # Validate VADPCM: flags, predictor index, state
                    if (i + 27 <= len(rom) and
                        all(rom[i + j] & 0xF0 == 0x00 for j in (0, 9, 18)) and
                        rom[i + 1] in [0x00, 0x01, 0x02] and  # Predictor index
                        all(-128 <= rom[i + j] <= 127 for j in range(2, 9))):  # State values
                        if potential_count['vadpcm'] < 10:
                            self.logger.info(f"Potential VADPCM at offset 0x{i:08x}")
                        potential_count['vadpcm'] += 1
                        yield {'offset': i, 'length': 9, 'type': 'vadpcm', 'uncomp_size': 0}
                        i += 27
                    else:
                        if invalid_count['vadpcm'] < 10:
                            self.logger.debug(f"Invalid VADPCM at 0x{i:08x}")
                        invalid_count['vadpcm'] += 1
                        i += 4
                else:
                    i += 4
                if i % 0x100000 == 0:
                    self.logger.debug(f"Audio scan at 0x{i:08x}, memory usage: {self.get_memory_usage():.2f} MB")
            # Scan MIO0 blocks for audio
            for mio0 in self.find_mio0_headers(rom):
                try:
                    decomp_data = self.decompress_mio0(rom, mio0['offset'], mio0['length'])
                    j = 0
                    while j < len(decomp_data) - 16:
                        if decomp_data[j:j+4] in [b'\x42\x4E\x4B\x20', b'\x53\x45\x51\x20']:
                            asset_type = 'ctl' if decomp_data[j:j+4] == b'\x42\x4E\x4B\x20' else 'seq'
                            if potential_count[asset_type] < 10:
                                self.logger.info(f"Potential {asset_type.upper()} in MIO0 at ROM offset 0x{mio0['offset']:08x}, MIO0 offset 0x{j:08x}")
                            potential_count[asset_type] += 1
                            length = 0
                            if asset_type == 'seq' and j + 8 <= len(decomp_data):
                                length = struct.unpack('>I', decomp_data[j+4:j+8])[0]
                            yield {
                                'offset': mio0['offset'],
                                'length': length,
                                'type': f'{asset_type}_mio0',
                                'uncomp_size': length,
                                'mio0_offset': j
                            }
                            self.logger.info(f"Found {asset_type.upper()} in MIO0 at ROM offset 0x{mio0['offset']:08x}, MIO0 offset 0x{j:08x}")
                        j += 4
                    gc.collect()  # Free memory after MIO0
                except Exception as e:
                    self.logger.error(f"Failed to scan MIO0 at 0x{mio0['offset']:08x}: {str(e)}")
            if invalid_count['vadpcm'] > 10:
                self.logger.info(f"Skipped {invalid_count['vadpcm'] - 10} additional invalid VADPCM frames")
        except Exception as e:
            self.logger.error(f"Audio scanning failed: {str(e)}")
        self.logger.info(f"Scanned audio: CTL={potential_count['ctl']}, SEQ={potential_count['seq']}, TBL={potential_count['tbl']}, VADPCM={potential_count['vadpcm']}")
        self.logger.debug(f"Memory usage: {self.get_memory_usage():.2f} MB")
        self.logger.debug("Exiting find_audio")

    def extract_audio(self, rom, offset, length, asset_type, output_dir):
        self.logger.debug(f"Entering extract_audio: offset=0x{offset:08x}, type={asset_type}")
        try:
            audio_dir = os.path.join(output_dir, 'audio')
            os.makedirs(audio_dir, exist_ok=True)
            output_path = os.path.join(audio_dir, f'audio_0x{offset:08x}.{asset_type.split("_")[0]}')
            if '_mio0' in asset_type:
                decomp_data = self.decompress_mio0(rom, offset, length)
                asset_type = asset_type.split('_')[0]
                output_path = os.path.join(audio_dir, f'audio_0x{offset:08x}_{asset_type}.bin')
                data = decomp_data
                if asset_type == 'seq' and len(data) >= 8:
                    length = struct.unpack('>I', data[4:8])[0]
                    data = data[:length] if length > 0 else data[:0x1000]
            elif asset_type in ['ctl', 'seq']:
                data = rom[offset:offset+length] if length else rom[offset:offset+0x1000]
            elif asset_type == 'tbl':
                data = rom[offset:offset+0x10000]
            elif asset_type == 'vadpcm':
                data = rom[offset:offset+9]
                output_path = output_path.replace('.vadpcm', '.raw')
            with open(output_path, 'wb') as f:
                f.write(data)
            self.logger.info(f"Saved {asset_type.upper()} to {output_path}")
        except Exception as e:
            self.logger.error(f"Failed to extract {asset_type.upper()} at 0x{offset:08x}: {str(e)}")
        finally:
            self.logger.debug("Exiting extract_audio")

    def get_dynamic_segments(self):
        self.logger.debug("Entering get_dynamic_segments")
        try:
            if self.rom_size < 0x1000:
                segments = [{'start': 0x0, 'end': self.rom_size, 'type': 'header', 'name': 'header'}]
            else:
                segments = [
                    {'start': 0x0, 'end': 0x1000, 'type': 'header', 'name': 'header'},
                    {'start': 0x1000, 'end': self.rom_size // 2, 'type': 'code', 'name': 'code'},
                    {'start': self.rom_size // 2, 'end': self.rom_size * 3 // 4, 'type': 'data', 'name': 'data'},
                    {'start': self.rom_size * 3 // 4, 'end': self.rom_size, 'type': 'assets', 'name': 'assets'}
                ]
            self.logger.debug("Exiting get_dynamic_segments")
            return segments
        except Exception as e:
            self.logger.error(f"Failed to get dynamic segments: {str(e)}")
            raise

    def run_splat(self, rom_path, output_dir):
        self.logger.debug(f"Entering run_splat: rom_path={rom_path}, output_dir={output_dir}")
        try:
            splat_yaml = os.path.join(output_dir, 'splat.yaml')
            target_path = os.path.join(output_dir, 'rom.z64')
            os.makedirs(output_dir, exist_ok=True)
            shutil.copy(rom_path, target_path)
            config = {
                'options': {
                    'platform': 'n64',
                    'basename': os.path.splitext(os.path.basename(rom_path))[0],
                    'base_path': output_dir,
                    'target_path': target_path,
                    'create_undefined_funcs_auto': True,
                    'create_undefined_syms_auto': True,
                    'asset_path': os.path.join(output_dir, 'assets')
                },
                'rom': rom_path,
                'baserom': os.path.basename(rom_path),
                'segments': self.get_dynamic_segments()
            }
            with open(splat_yaml, 'w') as f:
                yaml.dump(config, f)
            self.logger.info(f"Running n64splat on {rom_path}")
            subprocess.run(['splat', 'split', splat_yaml, '--verbose'], check=True, cwd=output_dir)
            self.logger.info(f"n64splat completed, output in {output_dir}")
            splat_config_path = os.path.join(output_dir, 'assets', 'config.yaml')
            if os.path.exists(splat_config_path):
                with open(splat_config_path, 'r') as f:
                    splat_config = yaml.safe_load(f)
                for asset in splat_config.get('assets', []):
                    yield {
                        'offset': int(asset['offset'], 16) if isinstance(asset['offset'], str) else asset['offset'],
                        'length': asset.get('length', 0),
                        'type': asset.get('type', 'unknown'),
                        'uncomp_size': asset.get('uncomp_size', 0)
                    }
            else:
                self.logger.warning("No splat config found")
        except Exception as e:
            self.logger.error(f"n64splat failed: {str(e)}")
        finally:
            self.logger.debug("Exiting run_splat")

    def write_yaml(self, rom_path, assets_iter, output_dir='.'):
        self.logger.debug(f"Entering write_yaml: output_dir={output_dir}")
        try:
            config = {
                'rom': rom_path,
                'endian': 'big',
                'arch': 'mips',
                'segments': self.get_dynamic_segments(),
                'symbols': 'symbols.txt',
                'assets': []
            }
            os.makedirs(output_dir, exist_ok=True)
            yaml_path = os.path.join(output_dir, 'config.yaml')
            with open(yaml_path, 'w') as f:
                for asset in assets_iter:
                    config['assets'].append({
                        'offset': f'0x{asset["offset"]:08x}',
                        'type': asset['type'],
                        'length': f'0x{asset["length"]:08x}' if asset['length'] else 'unknown',
                        'uncomp_size': f'0x{asset["uncomp_size"]:08x}' if asset.get('uncomp_size') else 'unknown'
                    })
                    if len(config['assets']) % 1000 == 0:
                        yaml.dump(config, f, sort_keys=False)
                        config['assets'] = []  # Reset to save memory
                        self.logger.debug(f"Flushed {len(config['assets'])} assets to YAML")
                if config['assets']:  # Write remaining assets
                    yaml.dump(config, f, sort_keys=False)
            self.logger.info(f"Wrote YAML to {yaml_path}")
        except Exception as e:
            self.logger.error(f"Failed to write YAML: {str(e)}")
        finally:
            self.logger.debug("Exiting write_yaml")

    def write_offset_pairs(self, assets_iter, output_dir='.'):
        self.logger.debug(f"Entering write_offset_pairs: output_dir={output_dir}")
        try:
            os.makedirs(output_dir, exist_ok=True)
            offset_path = os.path.join(output_dir, 'offset_pairs.txt')
            with open(offset_path, 'w') as f:
                for asset in assets_iter:
                    if asset['length']:
                        f.write(f'0x{asset["offset"]:08x},0x{asset["offset"] + asset["length"]:08x}\n')
            self.logger.info(f"Wrote offset pairs to {offset_path}")
        except Exception as e:
            self.logger.error(f"Failed to write offset pairs: {str(e)}")
        finally:
            self.logger.debug("Exiting write_offset_pairs")

    def write_summary(self, assets_iter, output_dir):
        self.logger.debug(f"Entering write_summary: output_dir={output_dir}")
        try:
            os.makedirs(output_dir, exist_ok=True)
            summary_path = os.path.join(output_dir, 'summary.txt')
            types = {}
            total_assets = 0
            with open(summary_path, 'w') as f:
                f.write(f"N64EA Asset Extraction Summary - {datetime.now()}\n")
                for asset in assets_iter:
                    total_assets += 1
                    types[asset['type']] = types.get(asset['type'], 0) + 1
                    f.write(f"{asset['type'].upper()} at Offset: 0x{asset['offset']:08x}, Length: {f'0x{asset['length']:08x}' if asset['length'] else 'unknown'}\n")
                    if total_assets % 1000 == 0:
                        f.write(f"\nIntermediate Total: {total_assets} assets\n")
                        f.flush()  # Save progress
                f.write(f"\nTotal Assets: {total_assets}\n")
                f.write("\nAsset Type Counts:\n")
                for t, count in types.items():
                    f.write(f"{t.upper()}: {count}\n")
            self.logger.info(f"Wrote summary to {summary_path}, total assets: {total_assets}")
        except Exception as e:
            self.logger.error(f"Failed to write summary: {str(e)}")
        finally:
            self.logger.debug("Exiting write_summary")

    def analyze_all(self, rom, options, progress_callback=None, cancel_event=None):
        self.logger.debug("Entering analyze_all")
        def combine_assets():
            tasks = []
            if options.get('mio0') and (not cancel_event or not cancel_event.is_set()):
                tasks.append(self.find_mio0_headers(rom, progress_callback))
            if options.get('yaz0') and (not cancel_event or not cancel_event.is_set()):
                tasks.append(self.find_yaz0_headers(rom, progress_callback))
            if options.get('textures') and (not cancel_event or not cancel_event.is_set()):
                tasks.append(self.find_textures(rom, progress_callback))
            if options.get('audio') and (not cancel_event or not cancel_event.is_set()):
                tasks.append(self.find_audio(rom, progress_callback))
            for task in tasks:
                if cancel_event and cancel_event.is_set():
                    self.logger.info("Analysis cancelled")
                    break
                try:
                    for asset in task:
                        yield asset
                except Exception as e:
                    self.logger.error(f"Task failed: {str(e)}")
        try:
            for asset in combine_assets():
                yield asset
        except MemoryError as e:
            self.logger.error(f"Memory error during analysis: {str(e)}")
        except Exception as e:
            self.logger.error(f"Concurrent analysis failed: {str(e)}")
        self.logger.debug(f"Memory usage: {self.get_memory_usage():.2f} MB")
        self.logger.debug("Exiting analyze_all")
