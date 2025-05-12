# N64EA
# Copyright (c) 2025 CanC-Code
# Licensed under the MIT License. See LICENSE file in the project root.

import tkinter as tk
from tkinter import filedialog, ttk, simpledialog
from rom_analyzer import RomAnalyzer
import logging
import os
import threading
import time
from datetime import datetime
import psutil

# Configure logging with timestamps
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('n64ea.log'),
        logging.StreamHandler()
    ]
)

class MainWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Initializing MainWindow")
        self.title("N64EA - N64 Extraction Assistant")
        self.geometry("800x600")
        self.progress_lock = threading.Lock()
        self.cancel_event = None
        self.pause_event = None
        self.asset_counts = {'mio0': 0, 'yaz0': 0, 'texture_ci4': 0, 'texture_ci8': 0, 'ctl': 0, 'seq': 0, 'tbl': 0, 'vadpcm': 0, 'ctl_mio0': 0, 'seq_mio0': 0}
        self.start_time = None

        # ROM selection
        self.rom_path = tk.StringVar(value="No ROM selected")
        tk.Button(self, text="Select ROM", command=self.select_rom).pack(pady=5)
        tk.Label(self, textvariable=self.rom_path).pack(pady=5)

        # Output folder selection
        self.output_dir = tk.StringVar(value="No output folder selected")
        tk.Button(self, text="Select or Create Output Folder", command=self.select_output_dir).pack(pady=5)
        tk.Label(self, textvariable=self.output_dir).pack(pady=5)

        # Analysis options
        self.mio0_var = tk.BooleanVar(value=True)
        self.yaz0_var = tk.BooleanVar()
        self.textures_var = tk.BooleanVar(value=True)
        self.audio_var = tk.BooleanVar(value=True)
        self.splat_var = tk.BooleanVar(value=True)
        self.yaml_var = tk.BooleanVar(value=True)
        self.offsets_var = tk.BooleanVar(value=True)
        tk.Checkbutton(self, text="Extract MIO0", variable=self.mio0_var).pack()
        tk.Checkbutton(self, text="Extract Yaz0", variable=self.yaz0_var).pack()
        tk.Checkbutton(self, text="Extract Textures (PNG)", variable=self.textures_var).pack()
        tk.Checkbutton(self, text="Extract Audio (CTL/SEQ/TBL/VADPCM)", variable=self.audio_var).pack()
        tk.Checkbutton(self, text="Use n64splat", variable=self.splat_var).pack()
        tk.Checkbutton(self, text="Generate YAML", variable=self.yaml_var).pack()
        tk.Checkbutton(self, text="Generate Offset Pairs", variable=self.offsets_var).pack()

        # Status and progress
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self, text="Status:").pack(pady=5)
        tk.Label(self, textvariable=self.status_var, font=("Arial", 12, "bold")).pack(pady=5)
        self.progress = ttk.Progressbar(self, maximum=100)
        self.progress.pack(fill="x", padx=10, pady=5)
        self.progress_label = tk.StringVar(value="Progress: 0%")
        tk.Label(self, textvariable=self.progress_label).pack(pady=5)
        self.resource_label = tk.StringVar(value="Memory: 0 MB, CPU: 0%, Peak: 0 MB")
        tk.Label(self, textvariable=self.resource_label).pack(pady=5)
        self.time_label = tk.StringVar(value="Time Remaining: Unknown")
        tk.Label(self, textvariable=self.time_label).pack(pady=5)

        # Control buttons
        self.run_button = tk.Button(self, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(pady=5)
        self.pause_button = tk.Button(self, text="Pause", command=self.pause_analysis, state=tk.DISABLED)
        self.pause_button.pack(pady=5)
        self.cancel_button = tk.Button(self, text="Cancel", command=self.cancel_analysis, state=tk.DISABLED)
        self.cancel_button.pack(pady=5)

        # Output log
        self.output = tk.Text(self, height=15)
        self.output_scroll = tk.Scrollbar(self, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=self.output_scroll.set)
        self.output_scroll.pack(side="right", fill="y")
        self.output.pack(fill="both", expand=True, padx=10, pady=5)
        self.logger.debug("MainWindow initialized")

    def select_rom(self):
        self.logger.debug("Entering select_rom")
        try:
            path = filedialog.askopenfilename(filetypes=[("N64 ROMs", "*.z64 *.v64 *.n64")])
            if path:
                self.rom_path.set(path)
                self.log_message(f"Selected ROM: {path}")
        except Exception as e:
            self.log_message(f"Error selecting ROM: {str(e)}")
        finally:
            self.logger.debug("Exiting select_rom")

    def select_output_dir(self):
        self.logger.debug("Entering select_output_dir")
        try:
            dir_path = filedialog.askdirectory(initialdir=os.path.expanduser("~/Desktop"))
            if dir_path:
                self.output_dir.set(dir_path)
                self.log_message(f"Selected output folder: {dir_path}")
            else:
                new_dir = simpledialog.askstring("Create Folder", "Enter new folder name:", parent=self)
                if new_dir:
                    dir_path = os.path.join(os.path.expanduser("~/Desktop"), new_dir)
                    os.makedirs(dir_path, exist_ok=True)
                    self.output_dir.set(dir_path)
                    self.log_message(f"Created output folder: {dir_path}")
        except Exception as e:
            self.log_message(f"Error creating folder: {str(e)}")
        finally:
            self.logger.debug("Exiting select_output_dir")

    def log_message(self, message):
        self.logger.debug(f"Logging message: {message}")
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.output.insert(tk.END, f"[{timestamp}] {message}\n")
        self.output.see(tk.END)
        logging.info(message)

    def update_progress(self, value, step):
        self.logger.debug(f"Updating progress: value={value}, step={step}")
        with self.progress_lock:
            try:
                self.progress['value'] = min(value, 100)
                self.progress_label.set(f"Progress: {int(value)}%")
                counts_str = ', '.join(f"{k.upper()}: {v}" for k, v in self.asset_counts.items() if v > 0)
                self.status_var.set(f"{step} ({counts_str})")
                # Use psutil directly since RomAnalyzer methods are not implemented
                mem_usage = psutil.Process().memory_info().rss / (1024 * 1024)  # MB
                cpu_usage = psutil.cpu_percent(interval=None)
                peak_memory = mem_usage  # Simplified, no peak tracking yet
                self.resource_label.set(f"Memory: {mem_usage:.2f} MB, CPU: {cpu_usage:.1f}%, Peak: {peak_memory:.2f} MB")
                if self.start_time and value > 0:
                    elapsed = time.time() - self.start_time
                    remaining = (elapsed / value) * (100 - value)
                    self.time_label.set(f"Time Remaining: {int(remaining)}s")
                self.update_idletasks()
            except Exception as e:
                self.logger.error(f"Failed to update progress: {str(e)}")

    def pause_analysis(self):
        self.logger.debug("Entering pause_analysis")
        try:
            if self.pause_event:
                if self.pause_event.is_set():
                    self.pause_event.clear()
                    self.pause_button.config(text="Pause")
                    self.log_message("Resuming analysis...")
                else:
                    self.pause_event.set()
                    self.pause_button.config(text="Resume")
                    self.log_message("Pausing analysis...")
        except Exception as e:
            self.log_message(f"Error pausing analysis: {str(e)}")
        finally:
            self.logger.debug("Exiting pause_analysis")

    def cancel_analysis(self):
        self.logger.debug("Entering cancel_analysis")
        try:
            if self.cancel_event:
                self.cancel_event.set()
                self.log_message("Cancelling analysis...")
                self.run_button.config(state=tk.NORMAL)
                self.pause_button.config(state=tk.DISABLED)
                self.cancel_button.config(state=tk.DISABLED)
        except Exception as e:
            self.log_message(f"Error cancelling analysis: {str(e)}")
        finally:
            self.logger.debug("Exiting cancel_analysis")

    def run_analysis(self):
        self.logger.debug("Entering run_analysis")
        try:
            if not self.rom_path.get() or self.rom_path.get() == "No ROM selected":
                self.log_message("Error: No ROM selected")
                return
            if not self.output_dir.get() or self.output_dir.get() == "No output folder selected":
                self.log_message("Error: No output folder selected")
                return
            self.run_button.config(state=tk.DISABLED)
            self.pause_button.config(state=tk.NORMAL, text="Pause")
            self.cancel_button.config(state=tk.NORMAL)
            self.cancel_event = threading.Event()
            self.pause_event = threading.Event()
            self.asset_counts = {k: 0 for k in self.asset_counts}
            self.start_time = time.time()
            self.progress['value'] = 0
            self.progress_label.set("Progress: 0%")
            self.resource_label.set("Memory: 0 MB, CPU: 0%, Peak: 0 MB")
            self.time_label.set("Time Remaining: Unknown")
            self.status_var.set("Starting analysis")
            # Removed references to temp_asset_file since it's not implemented
            threading.Thread(target=self._analyze_thread, daemon=True).start()
        except Exception as e:
            self.log_message(f"Error starting analysis: {str(e)}")
        finally:
            self.logger.debug("Exiting run_analysis")

    def _analyze_thread(self):
        self.logger.debug("Entering _analyze_thread")
        try:
            self.log_message(f"Analyzing {self.rom_path.get()}...")
            self.update_progress(0, "Initializing analysis")

            # Create RomAnalyzer instance now that we have rom_path and output_dir
            analyzer = RomAnalyzer(self.rom_path.get(), self.output_dir.get())

            # Simplified analysis using existing extract_assets method
            self.update_progress(20, "Extracting assets")
            analyzer.extract_assets()

            # Update asset counts (simplified, since extract_assets doesn't return assets yet)
            # We'll need to modify RomAnalyzer to return asset info in the future
            self.asset_counts = {
                'texture_ci4': len([offset for offset in analyzer.offsets if "CI4" in str(analyzer.rom_data[offset:offset+4]).upper()]),
                'texture_ci8': len([offset for offset in analyzer.offsets if "CI8" in str(analyzer.rom_data[offset:offset+4]).upper()]),
                'vadpcm': len([offset for offset in analyzer.offsets if "VADPCM" in str(analyzer.rom_data[offset:offset+4]).upper()]),
            }

            if self.cancel_event.is_set():
                self.log_message("Analysis cancelled")
                self.update_progress(0, "Analysis cancelled")
                return

            if self.pause_event.is_set():
                self.log_message("Paused: Waiting to resume...")
                self.pause_event.wait()

            self.update_progress(100, "Analysis complete")
            elapsed = time.time() - self.start_time
            self.log_message(f"Analysis completed in {elapsed:.2f} seconds")
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            self.update_progress(0, "Analysis failed")
        finally:
            self.run_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.DISABLED)
            self.cancel_button.config(state=tk.DISABLED)
            self.cancel_event = None
            self.pause_event = None
            self.start_time = None
            self.logger.debug("Exiting _analyze_thread")
