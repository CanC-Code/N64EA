import yaml
import os
import struct
import psutil
import json
from PIL import Image
import io
import wave
import numpy as np
from multiprocessing import Pool, cpu_count

class RomAnalyzer:
    def __init__(self, rom_path, output_folder, symbols_path=None):
        self.rom_path = rom_path
        self.output_folder = output_folder
        self.symbols_path = symbols_path
        self.rom_data = None
        self.is_big_endian = True
        self.segments = []
        self.offsets = []
        self.config = {}
        self.assets = []
        self.peak_memory = 0
        self.temp_asset_file = os.path.join(self.output_folder, "temp_assets.json")
        self.detected_offsets = set()  # Moved to instance variable for better tracking

        # Subfolders
        self.image_folder = os.path.join(self.output_folder, "images")
        self.audio_folder = os.path.join(self.output_folder, "audio")
        self.compressed_folder = os.path.join(self.output_folder, "compressed")
        self.segments_folder = os.path.join(self.output_folder, "segments")
        self.other_folder = os.path.join(self.output_folder, "other")
        os.makedirs(self.image_folder, exist_ok=True)
        os.makedirs(self.audio_folder, exist_ok=True)
        os.makedirs(self.compressed_folder, exist_ok=True)
        os.makedirs(self.segments_folder, exist_ok=True)
        os.makedirs(self.other_folder, exist_ok=True)

        # Check if rom_info.yaml exists
        rom_info_path = os.path.join(self.output_folder, "rom_info.yaml")
        if os.path.exists(rom_info_path):
            print(f"Loading existing ROM info from {rom_info_path}")
            with open(rom_info_path, "r") as f:
                self.config = yaml.safe_load(f)
            self.segments = self.config.get("segments", [])
            self.offsets = [int(offset, 16) for offset in self.config.get("offsets", [])]
        else:
            # Load the template
            try:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                template_path = os.path.join(script_dir, "template.yaml")
                with open(template_path, "r") as f:
                    self.config = yaml.safe_load(f)
            except FileNotFoundError:
                raise FileNotFoundError("template.yaml not found in src directory")

            # Load ROM data and detect endianness
            try:
                with open(self.rom_path, "rb") as f:
                    self.rom_data = f.read()
                self.detect_endianness()
            except FileNotFoundError:
                raise FileNotFoundError(f"ROM file not found at {self.rom_path}")

            # Extract ROM name and header information
            self.extract_rom_info()

            # Detect segments and offsets
            self.detect_segments()
            self.detect_offsets()

            # Save the analyzed data to rom_info.yaml
            self.save_rom_info()

    def detect_endianness(self):
        if len(self.rom_data) < 4:
            return
        magic = self.rom_data[0:4]
        if magic == b"\x80\x37\x12\x40":
            self.is_big_endian = True
        elif magic == b"\x40\x12\x37\x80":
            self.is_big_endian = False
            self.rom_data = bytearray(self.rom_data)
            for i in range(0, len(self.rom_data), 4):
                if i + 4 <= len(self.rom_data):
                    self.rom_data[i:i+4] = self.rom_data[i:i+4][::-1]
            self.rom_data = bytes(self.rom_data)

    def get_memory_usage(self):
        mem = psutil.Process().memory_info().rss / (1024 * 1024)
        self.peak_memory = max(self.peak_memory, mem)
        return mem

    def get_cpu_usage(self):
        return psutil.cpu_percent(interval=None)

    def extract_rom_info(self):
        self.config["rom_name"] = os.path.basename(self.rom_path)
        if len(self.rom_data) < 0x40:
            raise ValueError("ROM file is too small to contain a valid N64 header")
        header = self.rom_data[:0x40]
        fmt = ">I" if self.is_big_endian else "<I"
        self.config["header"] = {
            "pi_status": struct.unpack(fmt, header[0x00:0x04])[0],
            "clock_rate": struct.unpack(fmt, header[0x04:0x08])[0],
            "entry_point": struct.unpack(fmt, header[0x08:0x0C])[0],
            "release": struct.unpack(fmt, header[0x0C:0x10])[0],
            "crc1": struct.unpack(fmt, header[0x10:0x14])[0],
            "crc2": struct.unpack(fmt, header[0x14:0x18])[0],
            "game_title": header[0x20:0x34].decode("ascii", errors="ignore").strip(),
            "game_code": header[0x3B:0x3F].decode("ascii", errors="ignore").strip(),
            "version": header[0x3F]
        }
        self.config["endian"] = "big" if self.is_big_endian else "little"

    def detect_segments(self):
        self.segments = []
        self.segments.append([0, 0x40, "header"])
        
        entry_point = self.config["header"]["entry_point"]
        entry_point_offset = entry_point - 0x80000000
        if entry_point_offset < 0x40 or entry_point_offset >= len(self.rom_data):
            entry_point_offset = 0x40
        
        pos = 0x40
        code_start = pos
        code_end = None
        
        while pos < len(self.rom_data) - 4:
            if self.rom_data[pos:pos+4] == b"MIO0" or self.rom_data[pos:pos+4] == b"Yaz0":
                if code_end is None:
                    code_end = pos
                    self.segments.append([code_start, code_end, "code"])
                self.segments.append([pos, None, "assets"])
                pos += 0x1000
                break
            pos += 4
        
        if code_end is None:
            pos = entry_point_offset
            while pos < len(self.rom_data) - 4:
                if all(b == 0 for b in self.rom_data[pos:pos+0x100]):
                    code_end = pos
                    break
                pos += 4
            
            if code_end is None:
                code_end = len(self.rom_data) // 2
            self.segments.append([code_start, code_end, "code"])
        
        if len(self.segments) == 2:
            data_start = code_end
            data_end = len(self.rom_data) if pos >= len(self.rom_data) else pos
            if data_start < data_end:
                self.segments.append([data_start, data_end, "data"])
        
        if len(self.segments) > 2:
            self.segments[-1][1] = len(self.rom_data)
        else:
            if self.segments[-1][1] is None:
                self.segments[-1][1] = len(self.rom_data)
        
        print("Detected segments:", self.segments)

    def detect_asset_at_offset(self, pos):
        """Helper function to detect an asset at a given offset."""
        if pos in self.detected_offsets:
            return None, None

        # Detect MIO0
        if pos + 4 < len(self.rom_data) and self.rom_data[pos:pos+4] == b"MIO0":
            length = self.get_mio0_length(pos)
            self.detected_offsets.add(pos)
            return {"type": "mio0", "offset": pos, "length": length}, length if length else 0x1000

        # Detect Yaz0
        if pos + 4 < len(self.rom_data) and self.rom_data[pos:pos+4] == b"Yaz0":
            length = self.get_yaz0_length(pos)
            self.detected_offsets.add(pos)
            return {"type": "yaz0", "offset": pos, "length": length}, length if length else 0x1000

        # Detect CI4/CI8 textures
        if pos + 8 < len(self.rom_data):
            width = struct.unpack(">H", self.rom_data[pos:pos+2])[0]
            height = struct.unpack(">H", self.rom_data[pos+2:pos+4])[0]
            if 16 <= width <= 1024 and 16 <= height <= 1024:
                expected_size_ci4 = (width * height) // 2
                expected_size_ci8 = width * height
                palette_offset = None
                palette_search_pos = pos + 4
                while palette_search_pos < len(self.rom_data) - 512:
                    palette_data = self.rom_data[palette_search_pos:palette_search_pos+512]
                    if self.is_possible_palette(palette_data, fmt="ci4"):
                        palette_offset = palette_search_pos
                        break
                    palette_search_pos += 4

                if expected_size_ci4 >= 1024 and pos + 4 + expected_size_ci4 < len(self.rom_data):
                    self.detected_offsets.add(pos)
                    return {
                        "type": "texture_ci4",
                        "offset": pos,
                        "length": expected_size_ci4 + 4,
                        "width": width,
                        "height": height,
                        "palette_offset": palette_offset
                    }, expected_size_ci4 + 4
                elif expected_size_ci8 >= 2048 and pos + 4 + expected_size_ci8 < len(self.rom_data):
                    self.detected_offsets.add(pos)
                    return {
                        "type": "texture_ci8",
                        "offset": pos,
                        "length": expected_size_ci8 + 4,
                        "width": width,
                        "height": height,
                        "palette_offset": palette_offset
                    }, expected_size_ci8 + 4

        # Detect VADPCM audio
        if pos + 16 < len(self.rom_data):
            predictor_count = struct.unpack(">H", self.rom_data[pos:pos+2])[0]
            if 1 <= predictor_count <= 16:
                length = None
                scan_pos = pos + 16
                min_length = 256
                while scan_pos < len(self.rom_data) - 4:
                    if self.rom_data[scan_pos:scan_pos+4] in [b"MIO0", b"Yaz0"] or \
                       (scan_pos - pos >= min_length and struct.unpack(">H", self.rom_data[scan_pos:scan_pos+2])[0] in range(16, 1025)):
                        length = scan_pos - pos
                        break
                    if scan_pos - pos >= min_length and all(b == 0 for b in self.rom_data[scan_pos:scan_pos+64]):
                        length = scan_pos - pos
                        break
                    scan_pos += 4
                if length is None:
                    length = min(0x1000, len(self.rom_data) - pos)
                self.detected_offsets.add(pos)
                return {"type": "vadpcm", "offset": pos, "length": length}, length

        # Detect SEQ
        if pos + 4 < len(self.rom_data) and self.rom_data[pos:pos+4] == b"SEQ ":
            length = struct.unpack(">I", self.rom_data[pos+4:pos+8])[0]
            if length > 0 and pos + length < len(self.rom_data):
                self.detected_offsets.add(pos)
                return {"type": "seq", "offset": pos, "length": length}, length

        # Detect CTL/TBL
        if pos + 4 < len(self.rom_data) and self.rom_data[pos:pos+4] == b"CTL ":
            length = struct.unpack(">I", self.rom_data[pos+4:pos+8])[0]
            if length > 0 and pos + length < len(self.rom_data):
                self.detected_offsets.add(pos)
                return {"type": "ctl", "offset": pos, "length": length}, length
        if pos + 4 < len(self.rom_data) and self.rom_data[pos:pos+4] == b"TBL ":
            length = struct.unpack(">I", self.rom_data[pos+4:pos+8])[0]
            if length > 0 and pos + length < len(self.rom_data):
                self.detected_offsets.add(pos)
                return {"type": "tbl", "offset": pos, "length": length}, length

        return None, 4  # Default increment if no asset is detected

    def detect_offsets(self):
        self.offsets = []
        self.assets = []
        self.detected_offsets.clear()  # Ensure the set is empty

        # Split the ROM into chunks for parallel processing
        chunk_size = len(self.rom_data) // (cpu_count() * 2)
        chunks = [(i, min(i + chunk_size, len(self.rom_data) - 16)) for i in range(0, len(self.rom_data) - 16, chunk_size)]

        # Process each chunk in parallel
        with Pool() as pool:
            results = pool.starmap(self.detect_assets_in_chunk, chunks)

        # Combine results
        for chunk_assets in results:
            for asset, offset in chunk_assets:
                if asset and offset not in self.offsets:
                    self.offsets.append(offset)
                    self.assets.append(asset)
                    self._save_temp_assets()

        print("Detected offsets:", [hex(offset) for offset in self.offsets])

    def detect_assets_in_chunk(self, start, end):
        chunk_assets = []
        pos = start
        local_detected_offsets = set()

        while pos < end:
            if pos in local_detected_offsets or pos in self.detected_offsets:
                pos += 4
                continue

            asset, increment = self.detect_asset_at_offset(pos)
            if asset:
                chunk_assets.append((asset, asset["offset"]))
                local_detected_offsets.add(pos)
            pos += increment

        # Update global detected offsets
        self.detected_offsets.update(local_detected_offsets)
        return chunk_assets

    def is_possible_palette(self, data, fmt):
        expected_colors = 16 if fmt == "ci4" else 256
        if len(data) < expected_colors * 2:
            return False
        for i in range(0, expected_colors * 2, 2):
            color = struct.unpack(">H", data[i:i+2])[0]
            if (color & 0x1) == 0:
                return False
        return True

    def get_mio0_length(self, offset):
        if offset + 16 >= len(self.rom_data) or self.rom_data[offset:offset+4] != b"MIO0":
            return None
        compressed_length = struct.unpack(">I", self.rom_data[offset+8:offset+12])[0]
        return compressed_length + 16

    def get_yaz0_length(self, offset):
        if offset + 16 >= len(self.rom_data) or self.rom_data[offset:offset+4] != b"Yaz0":
            return None
        compressed_length = struct.unpack(">I", self.rom_data[offset+4:offset+8])[0]
        return compressed_length + 16

    def _save_temp_assets(self):
        with open(self.temp_asset_file, "a") as f:
            json.dump(self.assets, f)
            f.write("\n")

    def save_rom_info(self):
        self.config["segments"] = self.segments
        self.config["offsets"] = [hex(offset) for offset in self.offsets]
        output_path = os.path.join(self.output_folder, "rom_info.yaml")
        with open(output_path, "w") as f:
            yaml.dump(self.config, f)
        print(f"Saved ROM info to {output_path}")

    def decompress_mio0(self, data):
        if data[:4] != b"MIO0":
            raise ValueError("Not a valid MIO0 compressed file")
        return data

    def decompress_yaz0(self, data):
        if data[:4] != b"Yaz0":
            raise ValueError("Not a valid Yaz0 compressed file")
        return data

    def extract_texture(self, rom_data, offset, length, fmt, output_dir, width, height, palette_offset=None):
        if length is None or offset + length > len(rom_data):
            length = min(0x1000, len(rom_data) - offset)
        texture_data = rom_data[offset+4:offset+length]

        if fmt in ["ci4", "ci8"]:
            palette = None
            if palette_offset and palette_offset + 512 <= len(rom_data):
                palette_data = rom_data[palette_offset:palette_offset+512]
                palette = []
                num_colors = 16 if fmt == "ci4" else 256
                for i in range(0, num_colors * 2, 2):
                    color = struct.unpack(">H", palette_data[i:i+2])[0]
                    r = ((color >> 11) & 0x1F) * 255 // 31
                    g = ((color >> 6) & 0x1F) * 255 // 31
                    b = ((color >> 1) & 0x1F) * 255 // 31
                    palette.extend([r, g, b])

            if fmt == "ci4":
                pixels = bytearray(width * height * 3)
                for i in range(len(texture_data)):
                    byte = texture_data[i]
                    idx1 = (byte >> 4) * 3
                    idx2 = (byte & 0x0F) * 3
                    for j in range(3):
                        pixels[i*6 + j] = palette[idx1 + j] if palette else (byte >> 4) * 17
                        if i*2 + 1 < width * height:
                            pixels[i*6 + 3 + j] = palette[idx2 + j] if palette else (byte & 0x0F) * 17
            else:
                pixels = bytearray(width * height * 3)
                for i in range(len(texture_data)):
                    idx = texture_data[i] * 3
                    for j in range(3):
                        pixels[i*3 + j] = palette[idx + j] if palette else texture_data[i]

            image = Image.frombytes("RGB", (width, height), bytes(pixels))
            output_path = os.path.join(output_dir, f"texture_{fmt}_{hex(offset)}.png")
            image.save(output_path, "PNG")
        else:
            output_path = os.path.join(output_dir, f"texture_{fmt}_{hex(offset)}.bin")
            with open(output_path, "wb") as f:
                f.write(texture_data)
        return output_path

    def decode_vadpcm(self, audio_data):
        """Simplified VADPCM decoding to WAV (placeholder implementation)."""
        if len(audio_data) < 16:
            return None

        predictor_count = struct.unpack(">H", audio_data[0:2])[0]
        if not (1 <= predictor_count <= 16):
            return None

        # Placeholder: Assume a simple decoding (in reality, VADPCM requires proper predictor tables)
        # We'll treat the data as raw 4-bit ADPCM samples for demonstration
        samples = []
        for i in range(16, len(audio_data)):
            byte = audio_data[i]
            sample1 = (byte >> 4) - 8  # 4-bit signed
            sample2 = (byte & 0x0F) - 8
            samples.extend([sample1 * 2048, sample2 * 2048])  # Scale to 16-bit

        return np.array(samples, dtype=np.int16)

    def extract_audio(self, rom_data, offset, length, audio_type, output_dir):
        if length is None or offset + length > len(rom_data):
            length = min(0x1000, len(rom_data) - offset)
        audio_data = rom_data[offset:offset+length]

        if audio_type == "vadpcm":
            if length < 16:
                raise ValueError(f"Invalid VADPCM at offset 0x{offset:08x}: Data too short ({length} bytes)")
            predictor_count = struct.unpack(">H", audio_data[0:2])[0]
            if not (1 <= predictor_count <= 16):
                raise ValueError(f"Invalid VADPCM at offset 0x{offset:08x}: Invalid predictor count ({predictor_count})")

            # Decode VADPCM to WAV
            samples = self.decode_vadpcm(audio_data)
            if samples is not None:
                output_path = os.path.join(output_dir, f"audio_{audio_type}_{hex(offset)}.wav")
                with wave.open(output_path, "wb") as wav_file:
                    wav_file.setnchannels(1)  # Mono
                    wav_file.setsampwidth(2)  # 16-bit
                    wav_file.setframerate(32000)  # Typical N64 sample rate
                    wav_file.writeframes(samples.tobytes())
            else:
                output_path = os.path.join(output_dir, f"audio_{audio_type}_{hex(offset)}.bin")
                with open(output_path, "wb") as f:
                    f.write(audio_data)
        elif audio_type in ["seq", "ctl", "tbl"]:
            output_path = os.path.join(output_dir, f"audio_{audio_type}_{hex(offset)}.bin")
            with open(output_path, "wb") as f:
                f.write(audio_data)
        return output_path

    def extract_assets(self, asset_types=None):
        if asset_types is None:
            asset_types = {"mio0", "yaz0", "texture_ci4", "texture_ci8", "vadpcm", "seq", "ctl", "tbl"}

        for start, end, seg_type in self.segments:
            print(f"Processing segment {seg_type}: {hex(start)}-{hex(end)}")
            output_file = os.path.join(self.segments_folder, f"{seg_type}_{hex(start)}_{hex(end)}.bin")
            with open(output_file, "wb") as f:
                f.write(self.rom_data[start:end])

        for asset in self.assets:
            asset_type = asset["type"]
            offset = asset["offset"]
            length = asset.get("length")

            if asset_type not in asset_types:
                continue

            if asset_type == "mio0":
                if length is None or offset + length > len(self.rom_data):
                    length = min(0x1000, len(self.rom_data) - offset)
                data = self.rom_data[offset:offset+length]
                decompressed_data = self.decompress_mio0(data)
                output_file = os.path.join(self.compressed_folder, f"mio0_{hex(offset)}.bin")
                with open(output_file, "wb") as f:
                    f.write(decompressed_data)

            elif asset_type == "yaz0":
                if length is None or offset + length > len(self.rom_data):
                    length = min(0x1000, len(self.rom_data) - offset)
                data = self.rom_data[offset:offset+length]
                decompressed_data = self.decompress_yaz0(data)
                output_file = os.path.join(self.compressed_folder, f"yaz0_{hex(offset)}.bin")
                with open(output_file, "wb") as f:
                    f.write(decompressed_data)

            elif asset_type.startswith("texture_"):
                fmt = asset_type.split("_")[-1]
                width = asset.get("width")
                height = asset.get("height")
                palette_offset = asset.get("palette_offset")
                self.extract_texture(self.rom_data, offset, length, fmt, self.image_folder, width, height, palette_offset)

            elif asset_type in ["vadpcm", "seq", "ctl", "tbl"]:
                self.extract_audio(self.rom_data, offset, length, asset_type, self.audio_folder)

        return self.assets

    def compare_roms(self, other_rom_path):
        with open(other_rom_path, "rb") as f:
            other_data = f.read()
        
        if len(self.rom_data) != len(other_data):
            return {"error": f"ROM sizes differ: {len(self.rom_data)} vs {len(other_data)}"}
        
        differences = []
        for i in range(len(self.rom_data)):
            if self.rom_data[i] != other_data[i]:
                differences.append((i, self.rom_data[i], other_data[i]))
                if len(differences) >= 100:
                    break
        return differences

    def replace_asset(self, offset, new_data):
        if offset + len(new_data) > len(self.rom_data):
            raise ValueError("New data exceeds ROM size")
        self.rom_data = self.rom_data[:offset] + new_data + self.rom_data[offset + len(new_data):]
        with open(self.rom_path, "wb") as f:
            f.write(self.rom_data)
