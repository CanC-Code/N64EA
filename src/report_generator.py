import os
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, output_dir):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)

    def generate_report(self, assets, segments, rom_info):
        try:
            report_path = os.path.join(self.output_dir, 'reports', 'extraction_report.txt')
            os.makedirs(os.path.dirname(report_path), exist_ok=True)
            with open(report_path, 'w') as f:
                f.write("N64EA Extraction Report\n")
                f.write("=" * 50 + "\n")
                f.write(f"ROM Info: {rom_info}\n")
                f.write(f"Total Assets: {len(assets)}\n")
                f.write(f"Total Segments: {len(segments)}\n")
                f.write("\nAssets:\n")
                for asset in assets:
                    f.write(f"- Type: {asset['type']}, Offset: 0x{asset['offset']:08x}, Length: {asset.get('length', 'unknown')}\n")
                f.write("\nSegments:\n")
                for segment in segments:
                    f.write(f"- Start: 0x{segment[0]:08x}, End: 0x{segment[1]:08x}, Type: {segment[2]}\n")
            self.logger.info(f"Generated report at {report_path}")
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            raise
