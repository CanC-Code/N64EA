import yaml
import os
import struct
import psutil

class RomAnalyzer:
    def __init__(self, rom_path, output_folder, symbols_path=None):
        self.rom_path = rom_path
        self.output_folder = output_folder
        self.symbols_path = symbols_path
        self.rom_data = None
        self.segments = []
        self.offsets = []
        self.config = {}
        self.assets = []  # To store detected assets
        self.peak_memory = 0

        # Check if rom_info.yaml exists in the output folder
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
                with open("src/template.yaml", "r") as f:
                    self.config = yaml.safe_load(f)
            except FileNotFoundError:
                raise FileNotFoundError("template.yaml not found in src directory")

            # Load ROM data
            try:
                with open(self.rom_path, "rb") as f:
                    self.rom_data = f.read()
            except FileNotFoundError:
                raise FileNotFoundError(f"ROM file not found at {self.rom_path}")

            # Extract ROM name and header information
            self.extract_rom_info()

            # Dynamically detect segments and offsets
            self.detect_segments()
            self.detect_offsets()

            # Save the analyzed data to rom_info.yaml
            self.save_rom_info()

    def get_memory_usage(self):
        """Return current memory usage in MB."""
        mem = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
        self.peak_memory = max(self.peak_memory, mem)
        return mem

    def get_cpu_usage(self):
        """Return current CPU usage percentage."""
        return psutil.cpu_percent(interval=None)

    def extract_rom_info(self):
        """Extract ROM name and header information from the ROM."""
        # Extract ROM name from the file path
        self.config["rom_name"] = os.path.basename(self.rom_path)

        # Parse N64 header (first 0x40 bytes)
        if len(self.rom_data) < 0x40:
            raise ValueError("ROM file is too small to contain a valid N64 header")

        header = self.rom_data[:0x40]
        self.config["header"] = {
            "pi_status": struct.unpack(">I", header[0x00:0x04])[0],
            "clock_rate": struct.unpack(">I", header[0x04:0x08])[0],
            "entry_point": struct.unpack(">I", header[0x08:0x0C])[0],
            "release": struct.unpack(">I", header[0x0C:0x10])[0],
            "crc1": struct.unpack(">I", header[0x10:0x14])[0],
            "crc2": struct.unpack(">I", header[0x14:0x18])[0],
            "game_title": header[0x20:0x34].decode("ascii", errors="ignore").strip(),
            "game_code": header[0x3B:0x3F].decode("ascii", errors="ignore").strip(),
            "version": header[0x3F]
        }

    def detect_segments(self):
        """Dynamically detect segments in the ROM."""
        # 1. Header segment (first 0x40 bytes)
        self.segments.append([0, 0x40, "header"])

        # 2. Use entry point from header to find start of code
        entry_point = self.config["header"]["entry_point"]
        entry_point_offset = entry_point - 0x80000000
        if entry_point_offset < 0x40 or entry_point_offset >= len(self.rom_data):
            entry_point_offset = 0x40

        # Code segment starts after the header (or at entry point)
        code_start = max(0x40, entry_point_offset)
        self.segments.append([0x40, None, "code"])

        # 3. Scan for data and assets using known compression formats (MIO0, Yaz0)
        pos = code_start
        while pos < len(self.rom_data) - 4:
            if self.rom_data[pos:pos+4] == b"MIO0":
                if self.segments[-1][1] is None:
                    self.segments[-1][1] = pos
                self.segments.append([pos, None, "assets"])
                break
            elif self.rom_data[pos:pos+4] == b"Yaz0":
                if self.segments[-1][1] is None:
                    self.segments[-1][1] = pos
                self.segments.append([pos, None, "assets"])
                break
            pos += 4

        # 4. If assets found, insert a data segment between code and assets
        if len(self.segments) > 2:
            code_end = self.segments[1][1]
            assets_start = self.segments[2][0]
            if code_end < assets_start:
                self.segments.insert(2, [code_end, assets_start, "data"])
        else:
            if self.segments[-1][1] is None:
                self.segments[-1][1] = len(self.rom_data)

        # 5. Close the last segment (assets) at the end of the ROM
        if self.segments[-1][1] is None:
            self.segments[-1][1] = len(self.rom_data)

        print("Detected segments:", self.segments)

    def detect_offsets(self):
        """Dynamically detect offsets for assets (e.g., textures, audio)."""
        self.offsets = []
        self.assets = []
        pos = 0
        while pos < len(self.rom_data) - 16:
            # Detect MIO0
            if pos + 4 < len(self.rom_data) and self.rom_data[pos:pos+4] == b"MIO0":
                self.offsets.append(pos)
                self.assets.append({"type": "mio0", "offset": pos, "length": None})
                pos += 0x1000  # Skip a block
                continue

            # Detect Yaz0
            if pos + 4 < len(self.rom_data) and self.rom_data[pos:pos+4] == b"Yaz0":
                self.offsets.append(pos)
                self.assets.append({"type": "yaz0", "offset": pos, "length": None})
                pos += 0x1000
                continue

            # Detect CI4/CI8 textures
            if pos + 4 < len(self.rom_data):
                width = struct.unpack(">H", self.rom_data[pos:pos+2])[0]
                height = struct.unpack(">H", self.rom_data[pos+2:pos+4])[0]
                if 1 <= width <= 1024 and 1 <= height <= 1024:
                    expected_size_ci4 = (width * height) // 2
                    expected_size_ci8 = width * height
                    if pos + 4 + expected_size_ci4 < len(self.rom_data):
                        self.offsets.append(pos)
                        self.assets.append({"type": "texture_ci4", "offset": pos, "length": expected_size_ci4 + 4})
                        pos += 4 + expected_size_ci4
                        continue
                    elif pos + 4 + expected_size_ci8 < len(self.rom_data):
                        self.offsets.append(pos)
                        self.assets.append({"type": "texture_ci8", "offset": pos, "length": expected_size_ci8 + 4})
                        pos += 4 + expected_size_ci8
                        continue

            # Detect VADPCM audio
            if pos + 16 < len(self.rom_data):
                predictor_count = struct.unpack(">H", self.rom_data[pos:pos+2])[0]
                if 1 <= predictor_count <= 16:
                    self.offsets.append(pos)
                    self.assets.append({"type": "vadpcm", "offset": pos, "length": None})
                    pos += 0x1000
                    continue

            pos += 4

        print("Detected offsets:", [hex(offset) for offset in self.offsets])

    def save_rom_info(self):
        """Save the detected segments and offsets to rom_info.yaml in the output folder."""
        self.config["segments"] = self.segments
        self.config["offsets"] = [hex(offset) for offset in self.offsets]

        os.makedirs(self.output_folder, exist_ok=True)
        output_path = os.path.join(self.output_folder, "rom_info.yaml")
        with open(output_path, "w") as f:
            yaml.dump(self.config, f)

        print(f"Saved ROM info to {output_path}")

    def extract_texture(self, rom_data, offset, length, fmt, output_dir):
        """Extract a texture and save it as a raw binary file (placeholder for PNG conversion)."""
        if length is None or offset + length > len(rom_data):
            length = min(0x1000, len(rom_data) - offset)  # Default size if unknown
        texture_data = rom_data[offset:offset+length]
        output_path = os.path.join(output_dir, f"texture_{fmt}_{hex(offset)}.bin")
        with open(output_path, "wb") as f:
            f.write(texture_data)
        return output_path

    def extract_audio(self, rom_data, offset, length, audio_type, output_dir):
        """Extract an audio asset and save it as a raw binary file."""
        if length is None or offset + length > len(rom_data):
            length = min(0x1000, len(rom_data) - offset)
        audio_data = rom_data[offset:offset+length]
        output_path = os.path.join(output_dir, f"audio_{audio_type}_{hex(offset)}.bin")
        with open(output_path, "wb") as f:
            f.write(audio_data)
        return output_path

    def extract_assets(self):
        """Extract assets using detected segments and offsets, returning asset info."""
        # Extract segments
        for start, end, seg_type in self.segments:
            print(f"Processing segment {seg_type}: {hex(start)}-{hex(end)}")
            if seg_type == "header":
                header_data = self.rom_data[start:end]
                output_file = os.path.join(self.output_folder, "header.bin")
                with open(output_file, "wb") as f:
                    f.write(header_data)

        # Extract assets based on detected offsets
        for asset in self.assets:
            asset_type = asset["type"]
            offset = asset["offset"]
            length = asset.get("length")
            if asset_type.startswith("texture_"):
                fmt = asset_type.split("_")[-1]
                self.extract_texture(self.rom_data, offset, length, fmt, self.output_folder)
            elif asset_type in ["vadpcm", "ctl", "seq", "tbl", "ctl_mio0", "seq_mio0"]:
                self.extract_audio(self.rom_data, offset, length, asset_type, self.output_folder)
            elif asset_type in ["mio0", "yaz0"]:
                # Extract compressed data as raw binary (placeholder for decompression)
                if length is None or offset + length > len(self.rom_data):
                    length = min(0x1000, len(self.rom_data) - offset)
                data = self.rom_data[offset:offset+length]
                output_file = os.path.join(self.output_folder, f"{asset_type}_{hex(offset)}.bin")
                with open(output_file, "wb") as f:
                    f.write(data)

        return self.assets
