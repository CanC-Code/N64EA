# N64EA
# Copyright (c) 2025 CanC-Code
# Licensed under the MIT License. See LICENSE file in the project root.

import tkinter as tk
from tkinter import filedialog, ttk, simpledialog, messagebox, Toplevel
from rom_analyzer import RomAnalyzer
import logging
import os
import threading
import time
from datetime import datetime
import psutil
import json
from PIL import Image, ImageTk
import io

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
        self.geometry("1000x600")
        self.minsize(800, 500)
        self.progress_lock = threading.Lock()
        self.cancel_event = None
        self.pause_event = None
        self.asset_counts = {'mio0': 0, 'yaz0': 0, 'texture_ci4': 0, 'texture_ci8': 0, 'ctl': 0, 'seq': 0, 'tbl': 0, 'vadpcm': 0}
        self.start_time = None
        self.analyzer = None
        self.assets = []

        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.input_frame = ttk.LabelFrame(self.main_frame, text="Input Selection")
        self.input_frame.pack(fill="x", pady=5)

        self.rom_path = tk.StringVar(value="No ROM selected")
        ttk.Button(self.input_frame, text="Select ROM", command=self.select_rom).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.input_frame, textvariable=self.rom_path).grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.output_dir = tk.StringVar(value="No output folder selected")
        ttk.Button(self.input_frame, text="Select or Create Output Folder", command=self.select_output_dir).grid(row=1, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.input_frame, textvariable=self.output_dir).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        self.options_frame = ttk.LabelFrame(self.main_frame, text="Options")
        self.options_frame.pack(fill="x", pady=5)

        self.options_canvas = tk.Canvas(self.options_frame, height=100)
        self.options_scrollbar = ttk.Scrollbar(self.options_frame, orient="vertical", command=self.options_canvas.yview)
        self.options_inner_frame = ttk.Frame(self.options_canvas)

        self.options_inner_frame.bind("<Configure>", lambda e: self.options_canvas.configure(scrollregion=self.options_canvas.bbox("all")))
        self.options_canvas.configure(yscrollcommand=self.options_scrollbar.set)

        self.options_canvas.pack(side="left", fill="both", expand=True)
        self.options_scrollbar.pack(side="right", fill="y")
        self.options_canvas.create_window((0, 0), window=self.options_inner_frame, anchor="nw")

        self.asset_types_frame = ttk.LabelFrame(self.options_inner_frame, text="Select Asset Types to Extract")
        self.asset_types_frame.pack(fill="x", padx=5, pady=5)
        self.asset_vars = {}
        row = 0
        for asset_type in ['mio0', 'yaz0', 'texture_ci4', 'texture_ci8', 'vadpcm', 'seq', 'ctl', 'tbl']:
            var = tk.BooleanVar(value=True)
            self.asset_vars[asset_type] = var
            ttk.Checkbutton(self.asset_types_frame, text=f"Extract {asset_type.upper()}", variable=var).grid(row=row, column=0, sticky="w", padx=5, pady=2)
            row += 1

        self.additional_options_frame = ttk.LabelFrame(self.options_inner_frame, text="Additional Options")
        self.additional_options_frame.pack(fill="x", padx=5, pady=5)
        self.splat_var = tk.BooleanVar(value=False)
        self.yaml_var = tk.BooleanVar(value=True)
        self.offsets_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.additional_options_frame, text="Use n64splat (Experimental)", variable=self.splat_var).grid(row=0, column=0, sticky="w", padx=5, pady=2)
        ttk.Checkbutton(self.additional_options_frame, text="Generate YAML", variable=self.yaml_var).grid(row=1, column=0, sticky="w", padx=5, pady=2)
        ttk.Checkbutton(self.additional_options_frame, text="Generate Offset Pairs", variable=self.offsets_var).grid(row=2, column=0, sticky="w", padx=5, pady=2)

        self.compare_rom_path = tk.StringVar(value="No ROM selected for comparison")
        ttk.Button(self.additional_options_frame, text="Select ROM to Compare (Optional)", command=self.select_compare_rom).grid(row=3, column=0, padx=5, pady=5, sticky="w")
        ttk.Label(self.additional_options_frame, textvariable=self.compare_rom_path).grid(row=3, column=1, padx=5, pady=5, sticky="w")

        self.control_frame = ttk.Frame(self.main_frame)
        self.control_frame.pack(fill="x", pady=5)
        self.run_button = ttk.Button(self.control_frame, text="Run Analysis", command=self.run_analysis)
        self.run_button.grid(row=0, column=0, padx=5, pady=5)
        self.preview_button = ttk.Button(self.control_frame, text="Preview Assets", command=self.preview_assets, state=tk.DISABLED)
        self.preview_button.grid(row=0, column=1, padx=5, pady=5)
        self.pause_button = ttk.Button(self.control_frame, text="Pause", command=self.pause_analysis, state=tk.DISABLED)
        self.pause_button.grid(row=0, column=2, padx=5, pady=5)
        self.cancel_button = ttk.Button(self.control_frame, text="Cancel", command=self.cancel_analysis, state=tk.DISABLED)
        self.cancel_button.grid(row=0, column=3, padx=5, pady=5)

        self.status_frame = ttk.LabelFrame(self.main_frame, text="Status")
        self.status_frame.pack(fill="x", pady=5)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.status_frame, textvariable=self.status_var, font=("Arial", 12, "bold")).pack(pady=2)
        self.progress = ttk.Progressbar(self.status_frame, maximum=100)
        self.progress.pack(fill="x", padx=5, pady=2)
        self.progress_label = tk.StringVar(value="Progress: 0%")
        ttk.Label(self.status_frame, textvariable=self.progress_label).pack(pady=2)
        self.resource_label = tk.StringVar(value="Memory: 0 MB, CPU: 0%, Peak: 0 MB")
        ttk.Label(self.status_frame, textvariable=self.resource_label).pack(pady=2)
        self.time_label = tk.StringVar(value="Time Remaining: Unknown")
        ttk.Label(self.status_frame, textvariable=self.time_label).pack(pady=2)

        self.output_frame = ttk.LabelFrame(self.main_frame, text="Output Log")
        self.output_frame.pack(fill="both", expand=True, pady=5)
        self.output = tk.Text(self.output_frame, height=8)
        self.output_scroll = ttk.Scrollbar(self.output_frame, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=self.output_scroll.set)
        self.output_scroll.pack(side="right", fill="y")
        self.output.pack(fill="both", expand=True, padx=5, pady=5)
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
            messagebox.showerror("Error", f"Failed to select ROM: {str(e)}")
        finally:
            self.logger.debug("Exiting select_rom")

    def select_compare_rom(self):
        self.logger.debug("Entering select_compare_rom")
        try:
            path = filedialog.askopenfilename(filetypes=[("N64 ROMs", "*.z64 *.v64 *.n64")])
            if path:
                self.compare_rom_path.set(path)
                self.log_message(f"Selected ROM for comparison: {path}")
            else:
                self.compare_rom_path.set("No ROM selected for comparison")
                self.log_message("Cleared comparison ROM selection")
        except Exception as e:
            self.log_message(f"Error selecting comparison ROM: {str(e)}")
            messagebox.showerror("Error", f"Failed to select comparison ROM: {str(e)}")
        finally:
            self.logger.debug("Exiting select_compare_rom")

    def select_output_dir(self):
        self.logger.debug("Entering select_output_dir")
        try:
            dir_path = filedialog.askdirectory(initialdir=os.path.expanduser("~/Desktop"))
            if dir_path:
                self.output_dir.set(dir_path)
                self.log_message(f"Selected output folder: {dir_path}")
                self.log_message(f"Subfolders will be created: {os.path.join(dir_path, 'images')}, {os.path.join(dir_path, 'audio')}, {os.path.join(dir_path, 'compressed')}, {os.path.join(dir_path, 'segments')}")
            else:
                new_dir = simpledialog.askstring("Create Folder", "Enter new folder name:", parent=self)
                if new_dir:
                    dir_path = os.path.join(os.path.expanduser("~/Desktop"), new_dir)
                    os.makedirs(dir_path, exist_ok=True)
                    self.output_dir.set(dir_path)
                    self.log_message(f"Created output folder: {dir_path}")
                    self.log_message(f"Subfolders will be created: {os.path.join(dir_path, 'images')}, {os.path.join(dir_path, 'audio')}, {os.path.join(dir_path, 'compressed')}, {os.path.join(dir_path, 'segments')}")
        except Exception as e:
            self.log_message(f"Error creating folder: {str(e)}")
            messagebox.showerror("Error", f"Failed to select output folder: {str(e)}")
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
                mem_usage = psutil.Process().memory_info().rss / (1024 * 1024)
                cpu_usage = psutil.cpu_percent(interval=None)
                peak_memory = mem_usage
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
            messagebox.showerror("Error", f"Failed to pause/resume analysis: {str(e)}")
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
            messagebox.showerror("Error", f"Failed to cancel analysis: {str(e)}")
        finally:
            self.logger.debug("Exiting cancel_analysis")

    def run_analysis(self):
        self.logger.debug("Entering run_analysis")
        try:
            if not self.rom_path.get() or self.rom_path.get() == "No ROM selected":
                self.log_message("Error: No ROM selected")
                messagebox.showerror("Error", "Please select a ROM file")
                return
            if not self.output_dir.get() or self.output_dir.get() == "No output folder selected":
                self.log_message("Error: No output folder selected")
                messagebox.showerror("Error", "Please select an output folder")
                return
            self.run_button.config(state=tk.DISABLED)
            self.preview_button.config(state=tk.DISABLED)
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
            threading.Thread(target=self._analyze_thread, daemon=True).start()
        except Exception as e:
            self.log_message(f"Error starting analysis: {str(e)}")
            messagebox.showerror("Error", f"Failed to start analysis: {str(e)}")
        finally:
            self.logger.debug("Exiting run_analysis")

    def _analyze_thread(self):
        self.logger.debug("Entering _analyze_thread")
        self.analyzer = None
        try:
            self.log_message(f"Analyzing {self.rom_path.get()}...")
            self.update_progress(0, "Initializing analysis")

            self.analyzer = RomAnalyzer(self.rom_path.get(), self.output_dir.get())

            if os.path.exists(self.analyzer.temp_asset_file):
                os.remove(self.analyzer.temp_asset_file)

            self.update_progress(20, "Detecting assets")
            if self.splat_var.get():
                self.log_message("Using n64splat for segment detection (placeholder)")
            self.analyzer.detect_offsets()

            self.assets = []
            if os.path.exists(self.analyzer.temp_asset_file):
                with open(self.analyzer.temp_asset_file, 'r') as f:
                    for line in f:
                        temp_assets = json.loads(line.strip())
                        self.assets.extend(temp_assets)
                        for asset in temp_assets:
                            self.asset_counts[asset['type']] = self.asset_counts.get(asset['type'], 0) + 1

            if self.cancel_event.is_set():
                self.log_message("Analysis cancelled")
                self.update_progress(0, "Analysis cancelled")
                return

            if self.pause_event.is_set():
                self.log_message("Paused: Waiting to resume...")
                self.pause_event.wait()

            self.update_progress(50, "Extracting assets")
            selected_types = {k for k, v in self.asset_vars.items() if v.get()}
            self.analyzer.extract_assets(asset_types=selected_types)

            subfolders = {
                'images': self.analyzer.image_folder,
                'audio': self.analyzer.audio_folder,
                'compressed': self.analyzer.compressed_folder,
                'segments': self.analyzer.segments_folder
            }
            for subfolder_name, path in subfolders.items():
                file_count = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
                self.log_message(f"Extracted {file_count} files to {subfolder_name}/")

            if self.cancel_event.is_set():
                self.log_message("Analysis cancelled")
                self.update_progress(0, "Analysis cancelled")
                return

            if self.pause_event.is_set():
                self.log_message("Paused: Waiting to resume...")
                self.pause_event.wait()

            self.update_progress(80, "Comparing ROMs (if selected)")
            if self.compare_rom_path.get() and self.compare_rom_path.get() != "No ROM selected for comparison":
                self.log_message(f"Comparing {self.rom_path.get()} with {self.compare_rom_path.get()}...")
                differences = self.analyzer.compare_roms(self.compare_rom_path.get())
                if "error" in differences:
                    self.log_message(f"ROM Comparison Error: {differences['error']}")
                    messagebox.showerror("Error", differences['error'])
                else:
                    self.log_message(f"Found {len(differences)} differences between ROMs:")
                    for offset, byte1, byte2 in differences:
                        self.log_message(f"Offset 0x{offset:08x}: {byte1:02x} vs {byte2:02x}")
                    self.log_message(f"Comparison complete: {len(differences)} differences found.")

            self.update_progress(90, "Generating reports")
            self.log_message(f"Found {len(self.assets)} assets:")
            for asset in self.assets[:100]:
                msg = f"{asset['type'].upper()} at Offset: 0x{asset['offset']:08x}, Length: {f'0x{asset['length']:08x}' if asset['length'] else 'unknown'}"
                self.log_message(msg)
            if len(self.assets) > 100:
                self.log_message(f"...and {len(self.assets) - 100} more assets")

            self.update_progress(100, "Analysis complete")
            elapsed = time.time() - self.start_time
            self.log_message(f"Analysis completed in {elapsed:.2f} seconds")
            messagebox.showinfo("Success", f"Analysis completed in {elapsed:.2f} seconds. {len(self.assets)} assets extracted.")
            self.preview_button.config(state=tk.NORMAL)
        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            self.update_progress(0, "Analysis failed")
            messagebox.showerror("Error", f"Analysis failed: {str(e)}")
        finally:
            self.run_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.DISABLED)
            self.cancel_button.config(state=tk.DISABLED)
            self.cancel_event = None
            self.pause_event = None
            self.start_time = None
            if self.analyzer is not None and os.path.exists(self.analyzer.temp_asset_file):
                os.remove(self.analyzer.temp_asset_file)
            self.logger.debug("Exiting _analyze_thread")

    def preview_assets(self):
        if not self.assets:
            messagebox.showinfo("Info", "No assets to preview.")
            return

        preview_window = Toplevel(self)
        preview_window.title("Asset Preview")
        preview_window.geometry("800x600")

        # Left panel: Asset list and filtering
        left_frame = ttk.Frame(preview_window)
        left_frame.pack(side=tk.LEFT, fill="y", padx=5, pady=5)

        # Filter section
        filter_frame = ttk.LabelFrame(left_frame, text="Filter Assets")
        filter_frame.pack(fill="x", pady=5)
        filter_var = tk.StringVar(value="All")
        asset_types = ["All", "texture_ci4", "texture_ci8", "vadpcm", "seq", "ctl", "tbl", "mio0", "yaz0"]
        ttk.OptionMenu(filter_frame, filter_var, "All", *asset_types).pack(pady=5)

        asset_listbox = tk.Listbox(left_frame, height=20, width=50)
        asset_listbox.pack(fill="y", pady=5)

        # Right panel: Preview
        preview_frame = ttk.Frame(preview_window)
        preview_frame.pack(side=tk.RIGHT, fill="both", expand=True, padx=5, pady=5)
        image_label = ttk.Label(preview_frame)
        image_label.pack(fill="both", expand=True)

        def update_asset_list():
            asset_listbox.delete(0, tk.END)
            filter_type = filter_var.get()
            filtered_assets = self.assets if filter_type == "All" else [asset for asset in self.assets if asset['type'] == filter_type]
            for asset in filtered_assets:
                asset_listbox.insert(tk.END, f"{asset['type'].upper()} at 0x{asset['offset']:08x}")

        def replace_asset():
            selected = asset_listbox.curselection()
            if not selected:
                messagebox.showinfo("Info", "Please select an asset to replace.")
                return
            filter_type = filter_var.get()
            filtered_assets = self.assets if filter_type == "All" else [asset for asset in self.assets if asset['type'] == filter_type]
            asset = filtered_assets[selected[0]]
            new_file = filedialog.askopenfilename(title=f"Select new file for {asset['type']} at 0x{asset['offset']:08x}")
            if new_file:
                with open(new_file, "rb") as f:
                    new_data = f.read()
                try:
                    self.analyzer.replace_asset(asset['offset'], new_data)
                    self.log_message(f"Replaced {asset['type']} at 0x{asset['offset']:08x} with {new_file}")
                    messagebox.showinfo("Success", "Asset replaced successfully.")
                except Exception as e:
                    self.log_message(f"Error replacing asset: {str(e)}")
                    messagebox.showerror("Error", f"Failed to replace asset: {str(e)}")

        ttk.Button(preview_frame, text="Replace Selected Asset", command=replace_asset).pack(pady=5)

        def update_preview(event):
            selected = asset_listbox.curselection()
            if not selected:
                return
            filter_type = filter_var.get()
            filtered_assets = self.assets if filter_type == "All" else [asset for asset in self.assets if asset['type'] == filter_type]
            asset = filtered_assets[selected[0]]
            if asset['type'].startswith("texture_"):
                fmt = asset['type'].split("_")[-1]
                width = asset.get("width")
                height = asset.get("height")
                palette_offset = asset.get("palette_offset")
                texture_data = self.analyzer.rom_data[asset['offset']+4:asset['offset']+asset['length']]
                
                if fmt == "ci4":
                    pixels = bytearray(width * height * 3)
                    palette = None
                    if palette_offset:
                        palette_data = self.analyzer.rom_data[palette_offset:palette_offset+32]
                        palette = []
                        for i in range(0, 32, 2):
                            color = struct.unpack(">H", palette_data[i:i+2])[0]
                            r = ((color >> 11) & 0x1F) * 255 // 31
                            g = ((color >> 6) & 0x1F) * 255 // 31
                            b = ((color >> 1) & 0x1F) * 255 // 31
                            palette.extend([r, g, b])
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
                    palette = None
                    if palette_offset:
                        palette_data = self.analyzer.rom_data[palette_offset:palette_offset+512]
                        palette = []
                        for i in range(0, 512, 2):
                            color = struct.unpack(">H", palette_data[i:i+2])[0]
                            r = ((color >> 11) & 0x1F) * 255 // 31
                            g = ((color >> 6) & 0x1F) * 255 // 31
                            b = ((color >> 1) & 0x1F) * 255 // 31
                            palette.extend([r, g, b])
                    for i in range(len(texture_data)):
                        idx = texture_data[i] * 3
                        for j in range(3):
                            pixels[i*3 + j] = palette[idx + j] if palette else texture_data[i]

                image = Image.frombytes("RGB", (width, height), bytes(pixels))
                max_size = 400
                image.thumbnail((max_size, max_size))
                photo = ImageTk.PhotoImage(image)
                image_label.configure(image=photo)
                image_label.image = photo
            else:
                image_label.configure(image=None, text="Preview not available for this asset type.")

        filter_var.trace("w", lambda *args: update_asset_list())
        asset_listbox.bind('<<ListboxSelect>>', update_preview)
        update_asset_list()
