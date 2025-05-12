import yaml
import os
import struct

class RomAnalyzer:
    def __init__(self, rom_path, output_folder, symbols_path=None):
        self.rom_path = rom_path
        self.output_folder = output_folder
        self.symbols_path = symbols_path
        self.rom_data = None
        self.segments = []
        self.offsets = []
        self.config = {}

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
        entry_point_offset = entry_point - 0x80000000  # Adjust for N64 base address
        if entry_point_offset < 0x40 or entry_point_offset >= len(self.rom_data):
            entry_point_offset = 0x40  # Fallback to after header if invalid

        # Code segment starts after the header (or at entry point)
        code_start = max(0x40, entry_point_offset)
        self.segments.append([0x40, None, "code"])

        # 3. Scan for data and assets using known compression formats (MIO0, Yaz0)
        pos = code_start
        while pos < len(self.rom_data) - 4:
            # Check for MIO0 (common compression format in N64 ROMs)
            if self.rom_data[pos:pos+4] == b"MIO0":
                if self.segments[-1][1] is None:  # Close the code segment
                    self.segments[-1][1] = pos
                self.segments.append([pos, None, "assets"])
                break
            # Check for Yaz0 (another common compression format)
            elif self.rom_data[pos:pos+4] == b"Yaz0":
                if self.segments[-1][1] is None:  # Close the code segment
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
            # If no assets found, assume data extends to the end of the ROM
            if self.segments[-1][1] is None:
                self.segments[-1][1] = len(self.rom_data)

        # 5. Close the last segment (assets) at the end of the ROM
        if self.segments[-1][1] is None:
            self.segments[-1][1] = len(self.rom_data)

        print("Detected segments:", self.segments)

    def detect_offsets(self):
        """Dynamically detect offsets for assets (e.g., textures, audio)."""
        pos = 0
        while pos < len(self.rom_data) - 16:  # Ensure enough bytes for pattern matching
            # Detect CI4/CI8 textures (simplified check for texture headers)
            # N64 textures often have a header with width/height/format
            # Check for plausible texture format identifiers
            if pos + 4 < len(self.rom_data):
                # Look for texture format bytes (simplified, based on common N64 texture formats)
                # CI4 and CI8 textures often have specific byte patterns in tools like n64split
                # Here, we check for a plausible width/height (2 bytes each) followed by data
                width = struct.unpack(">H", self.rom_data[pos:pos+2])[0]
                height = struct.unpack(">H", self.rom_data[pos+2:pos+4])[0]
                # Check if width and height are reasonable (e.g., between 1 and 1024)
                if 1 <= width <= 1024 and 1 <= height <= 1024:
                    # Check for texture data following the header (simplified heuristic)
                    # CI4 uses 4 bits per pixel, CI8 uses 8 bits per pixel
                    expected_size_ci4 = (width * height) // 2  # 4 bits per pixel
                    expected_size_ci8 = width * height         # 8 bits per pixel
                    if pos + 4 + expected_size_ci4 < len(self.rom_data):
                        self.offsets.append(pos)
                        pos += 4 + expected_size_ci4
                        continue
                    elif pos + 4 + expected_size_ci8 < len(self.rom_data):
                        self.offsets.append(pos)
                        pos += 4 + expected_size_ci8
                        continue

            # Detect VADPCM audio
            # VADPCM audio in N64 ROMs often starts with a header indicating predictors
            # Look for a pattern that might indicate VADPCM audio (simplified)
            # VADPCM headers typically have a predictor count and coefficients
            if pos + 16 < len(self.rom_data):
                # Check for a plausible VADPCM header
                # Predictor count (2 bytes) followed by coefficients (simplified check)
                predictor_count = struct.unpack(">H", self.rom_data[pos:pos+2])[0]
                if 1 <= predictor_count <= 16:  # Reasonable range for VADPCM predictors
                    # Assume this is a VADPCM block (further validation needed in practice)
                    self.offsets.append(pos)
                    # Skip a reasonable block size (e.g., 0x1000 bytes, adjust as needed)
                    pos += 0x1000
                    continue

            pos += 4  # Increment by 4 bytes to align with typical data boundaries

        print("Detected offsets:", [hex(offset) for offset in self.offsets])

    def save_rom_info(self):
        """Save the detected segments and offsets to rom_info.yaml in the output folder."""
        # Update the config with detected data
        self.config["segments"] = self.segments
        self.config["offsets"] = [hex(offset) for offset in self.offsets]

        # Ensure the output folder exists
        os.makedirs(self.output_folder, exist_ok=True)

        # Save to rom_info.yaml in the output folder
        output_path = os.path.join(self.output_folder, "rom_info.yaml")
        with open(output_path, "w") as f:
            yaml.dump(self.config, f)

        print(f"Saved ROM info to {output_path}")

    def extract_assets(self):
        """Extract assets using detected segments and offsets."""
        for start, end, seg_type in self.segments:
            print(f"Processing segment {seg_type}: {hex(start)}-{hex(end)}")
            # Placeholder for actual extraction logic
            # Example: Extract header
            if seg_type == "header":
                header_data = self.rom_data[start:end]
                output_file = os.path.join(self.output_folder, "header.bin")
                with open(output_file, "wb") as f:
                    f.write(header_data)

        for offset in self.offsets:
            print(f"Extracting asset at offset {hex(offset)}")
            # Placeholder for actual asset extraction
            # Example: Extract a small chunk of data at each offset
            chunk_size = 0x1000  # Example size, adjust as needed
            if offset + chunk_size <= len(self.rom_data):
                asset_data = self.rom_data[offset:offset+chunk_size]
                output_file = os.path.join(self.output_folder, f"asset_{hex(offset)}.bin")
                with open(output_file, "wb") as f:
                    f.write(asset_data)
