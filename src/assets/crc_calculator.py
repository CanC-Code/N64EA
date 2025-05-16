import logging

logger = logging.getLogger(__name__)

class CRCCalculator:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Initializing CRCCalculator")
        self.logger.debug("CRCCalculator initialized")

    def calculate_crc(self, data):
        """Calculate the CRC checksum for the given data."""
        try:
            crc = 0
            for byte in data:
                crc = (crc + byte) & 0xFFFFFFFF
            self.logger.debug(f"Calculated CRC: 0x{crc:08x}")
            return crc
        except Exception as e:
            self.logger.error(f"Failed to calculate CRC: {e}")
            raise

    def update_crc(self, rom_path):
        """Update the CRC fields in the ROM file."""
        try:
            with open(rom_path, 'r+b') as f:
                rom_data = f.read(0x1000)
                crc1 = self.calculate_crc(rom_data[0x10:0x14])
                crc2 = self.calculate_crc(rom_data[0x14:0x18])
                f.seek(0x10)
                f.write(crc1.to_bytes(4, 'big'))
                f.seek(0x14)
                f.write(crc2.to_bytes(4, 'big'))
            self.logger.debug(f"Updated CRC in {rom_path}")
        except Exception as e:
            self.logger.error(f"Failed to update CRC: {e}")
            raise
