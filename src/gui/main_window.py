import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import time
import threading
import logging
from gui.text_handler import TextWidgetHandler
from analysis.rom_analyzer import RomAnalyzer
from analysis.splat_integration import SplatIntegration
from report_generator import ReportGenerator
from PIL import Image, ImageTk
import pygame
from OpenGL.GL import *
from OpenGL.GLU import *

logger = logging.getLogger(__name__)

class MainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("N64EA - N64 Extraction & Analysis")
        self.root.geometry("800x600")
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Initializing MainWindow")
        self.setup_gui()
        self.setup_logging()
        self.setup_opengl()
        self.assets = []
        self.asset_counts = {}
        self.cancel_event = None
        self.pause_event = None
        self.start_time = None
        self.analyzer = None
        self.splat_integration = None
        self.report_generator = None
        self.stop_event = threading.Event()
        self.is_shutting_down = False
        self.logger.debug("MainWindow initialized")

    def setup_gui(self):
        self.rom_path = tk.StringVar(value="No ROM selected")
        self.output_dir = tk.StringVar(value="No output folder selected")
        self.compare_rom_path = tk.StringVar(value="No ROM selected for comparison")
        self.splat_var = tk.BooleanVar(value=True)
        self.asset_vars = {
            'textures': tk.BooleanVar(value=True),
            'audio': tk.BooleanVar(value=True),
            'compressed': tk.BooleanVar(value=True),
            'models': tk.BooleanVar(value=True)
        }

        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(frame, text="ROM File:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.rom_path, width=50).grid(row=0, column=1)
        ttk.Button(frame, text="Browse", command=self.select_rom).grid(row=0, column=2)

        ttk.Label(frame, text="Output Folder:").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.output_dir, width=50).grid(row=1, column=1)
        ttk.Button(frame, text="Browse").grid(row=1, column=2)

        ttk.Label(frame, text="Compare ROM (Optional):").grid(row=2, column=0, sticky=tk.W)
        ttk.Entry(frame, textvariable=self.compare_rom_path, width=50).grid(row=2, column=1)
        ttk.Button(frame, text="Browse", command=self.select_compare_rom).grid(row=2, column=2)

        ttk.Checkbutton(frame, text="Use n64splat for detection", variable=self.splat_var).grid(row=3, column=0, columnspan=3, sticky=tk.W)

        ttk.Label(frame, text="Asset Types to Extract:").grid(row=4, column=0, sticky=tk.W)
        for i, (asset_type, var) in enumerate(self.asset_vars.items()):
            ttk.Checkbutton(frame, text=asset_type.capitalize(), variable=var).grid(row=4+i//2, column=1+i%2, sticky=tk.W)

        self.run_button = ttk.Button(frame, text="Run Analysis", command=self.run_analysis)
        self.run_button.grid(row=6, column=0, sticky=tk.W)

        self.pause_button = ttk.Button(frame, text="Pause", command=self.pause_analysis, state=tk.DISABLED)
        self.pause_button.grid(row=6, column=1, sticky=tk.W)

        self.cancel_button = ttk.Button(frame, text="Cancel", command=self.cancel_analysis, state=tk.DISABLED)
        self.cancel_button.grid(row=6, column=2, sticky=tk.W)

        self.preview_button = ttk.Button(frame, text="Preview Asset", command=self.preview_asset, state=tk.DISABLED)
        self.preview_button.grid(row=7, column=0, sticky=tk.W)

        self.rebuild_button = ttk.Button(frame, text="Rebuild ROM", command=self.rebuild_rom, state=tk.DISABLED)
        self.rebuild_button.grid(row=7, column=1, sticky=tk.W)

        self.progress = ttk.Progressbar(frame, length=400, mode='determinate')
        self.progress.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E))

        self.progress_label = ttk.Label(frame, text="Ready")
        self.progress_label.grid(row=9, column=0, columnspan=3, sticky=tk.W)

        self.log_text = tk.Text(frame, height=10, width=70)
        self.log_text.grid(row=10, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.asset_list = ttk.Treeview(frame, columns=('Type', 'Offset', 'Length'), show='headings')
        self.asset_list.heading('Type', text='Asset Type')
        self.asset_list.heading('Offset', text='Offset')
        self.asset_list.heading('Length', text='Length')
        self.asset_list.grid(row=11, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.asset_list.bind('<<TreeviewSelect>>', self.on_asset_select)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(10, weight=1)
        frame.rowconfigure(11, weight=1)

    def setup_logging(self):
        self.log_text_handler = TextWidgetHandler(self.log_text, self.root)
        self.log_text_handler.setFormatter(logging.Formatter('%(message)s'))
        self.logger.addHandler(self.log_text_handler)

    def setup_opengl(self):
        try:
            pygame.display.set_mode((400, 300), pygame.OPENGL | pygame.DOUBLEBUF)
            glClearColor(0.0, 0.0, 0.0, 1.0)
            glEnable(GL_DEPTH_TEST)
            gluPerspective(45, 400/300, 0.1, 50.0)
            glTranslatef(0.0, 0.0, -5)
            self.logger.debug("OpenGL initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize OpenGL: {e}")
            messagebox.showerror("Error", f"OpenGL initialization failed: {e}")

    def select_rom(self):
        self.logger.debug("Entering select_rom")
        rom_file = filedialog.askopenfilename(filetypes=[("N64 ROMs", "*.z64 *.n64 *.v64")])
        if rom_file:
            self.rom_path.set(rom_file)
            self.log_message(f"Selected ROM: {rom_file}")
        self.logger.debug("Exiting select_rom")

    def select_output_dir(self, default_dir=None):
        self.logger.debug("MainWindow select_output_dir called (should be overridden)")
        messagebox.showwarning("Warning", "Output directory selection should be handled by N64ExtractorApp")

    def select_compare_rom(self):
        compare_rom = filedialog.askopenfilename(filetypes=[("N64 ROMs", "*.z64 *.n64 *.v64")])
        if compare_rom:
            self.compare_rom_path.set(compare_rom)
            self.log_message(f"Selected comparison ROM: {compare_rom}")

    def log_message(self, message):
        self.logger.debug(f"Entering log_message: {message}")
        self.logger.info(message)
        self.logger.debug("Exiting log_message")

    def update_progress(self, value, step):
        self.logger.debug(f"Entering update_progress: value={value}, step={step}")
        try:
            self.progress['value'] = value
            self.progress_label['text'] = f"{step} ....."
            self.root.update_idletasks()
        except tk.TclError:
            self.logger.debug("Progress update skipped due to TclError")
        except Exception as e:
            self.logger.error(f"Failed to update progress: {e}")
        self.logger.debug("Exiting update_progress")

    def run_analysis(self):
        self.logger.debug("Entering run_analysis")
        if not self.rom_path.get() or self.rom_path.get() == "No ROM selected":
            self.root.after(0, lambda: messagebox.showerror("Error", "Please select a ROM file"))
            return
        if not self.output_dir.get() or self.output_dir.get() == "No output folder selected":
            self.root.after(0, lambda: messagebox.showerror("Error", "Please select an output folder"))
            return
        self.run_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.NORMAL)
        self.cancel_button.config(state=tk.NORMAL)
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()
        self.stop_event.clear()
        self.start_time = time.time()
        threading.Thread(target=self._analyze_thread, daemon=True).start()
        self.logger.debug("Exiting run_analysis")

    def _analyze_thread(self):
        self.logger.debug("Entering _analyze_thread")
        def queue_log_message(msg):
            self.root.after(0, lambda: self.log_message(msg))
        
        def queue_progress_update(value, step):
            self.root.after(0, lambda: self.update_progress(value, step))
        
        def queue_messagebox(title, msg, error=False):
            self.root.after(0, lambda: messagebox.showerror(title, msg) if error else messagebox.showinfo(title, msg))
        
        try:
            rom_path = self.rom_path.get()
            output_dir = self.output_dir.get()
            compare_rom_path = self.compare_rom_path.get()
            splat_enabled = self.splat_var.get()
            asset_types = {k for k, v in self.asset_vars.items() if v.get()}
            
            queue_log_message(f"Analyzing {rom_path}...")
            queue_progress_update(0, "Initializing analysis")
            if self.cancel_event.is_set():
                queue_log_message("Analysis cancelled")
                queue_progress_update(0, "Analysis cancelled")
                return
            self.analyzer = RomAnalyzer(rom_path, output_dir)
            self.report_generator = ReportGenerator(output_dir)
            if os.path.exists(self.analyzer.temp_asset_file):
                self.logger.debug("Removing existing temp_assets.json")
                os.remove(self.analyzer.temp_asset_file)
            queue_progress_update(20, "Detecting assets")
            if self.pause_event.is_set():
                queue_log_message("Paused: Waiting to resume...")
                self.pause_event.wait()
            if self.cancel_event.is_set():
                queue_log_message("Analysis cancelled")
                queue_progress_update(0, "Analysis cancelled")
                return
            if splat_enabled and self.splat_integration:
                queue_log_message("Using n64splat for segment and asset detection")
                self.splat_integration.run_splat(self.analyzer)
            self.analyzer.detect_offsets()
            if self.stop_event.is_set() or self.cancel_event.is_set():
                queue_log_message("Analysis cancelled or interrupted")
                queue_progress_update(0, "Analysis cancelled")
                return
            self.assets = self.analyzer.assets
            if not self.assets:
                queue_log_message("No assets detected")
            else:
                queue_log_message(f"Detected {len(self.assets)} assets")
                for asset in self.assets:
                    self.asset_counts[asset['type']] = self.asset_counts.get(asset['type'], 0) + 1
                    self.root.after(0, lambda a=asset: self.asset_list.insert('', 'end', values=(
                        a['type'],
                        hex(a['offset']),
                        hex(a['length']) if 'length' in a else 'unknown'
                    )))
            queue_progress_update(50, "Extracting assets")
            if self.pause_event.is_set():
                queue_log_message("Paused: Waiting to resume...")
                self.pause_event.wait()
            if self.cancel_event.is_set():
                queue_log_message("Analysis cancelled")
                queue_progress_update(0, "Analysis cancelled")
                return
            total_assets = len(self.assets)
            for i, asset in enumerate(self.assets):
                if self.cancel_event.is_set():
                    queue_log_message("Extraction cancelled")
                    queue_progress_update(50, "Extraction cancelled")
                    return
                self.analyzer.extract_asset(asset, asset_types)
                progress = 50 + (i + 1) / total_assets * 30
                queue_progress_update(progress, f"Extracting asset {i+1}/{total_assets}")
            subfolders = {
                'images': self.analyzer.image_folder,
                'audio': self.analyzer.audio_folder,
                'compressed': self.analyzer.compressed_folder,
                'segments': self.analyzer.segments_folder,
                'other': self.analyzer.other_folder
            }
            for subfolder_name, path in subfolders.items():
                file_count = len([f for f in os.listdir(path) if os.path.isfile(os.path.join(path, f))])
                queue_log_message(f"Extracted {file_count} files to {subfolder_name}/")
            if self.stop_event.is_set() or self.cancel_event.is_set():
                queue_log_message("Analysis cancelled or interrupted")
                queue_progress_update(0, "Analysis cancelled")
                return
            queue_progress_update(80, "Comparing ROMs (if selected)")
            if compare_rom_path and compare_rom_path != "No ROM selected for comparison":
                queue_log_message(f"Comparing {rom_path} with {compare_rom_path}...")
                differences = self.analyzer.compare_roms(compare_rom_path)
                if isinstance(differences, dict) and "error" in differences:
                    queue_log_message(f"ROM Comparison Error: {differences['error']}")
                    queue_messagebox("Error", differences['error'], error=True)
                else:
                    queue_log_message(f"Found {len(differences)} differences between ROMs:")
                    for offset, byte1, byte2 in differences[:100]:
                        queue_log_message(f"Offset 0x{offset:08x}: {byte1:02x} vs {byte2:02x}")
                    if len(differences) > 100:
                        queue_log_message(f"...and {len(differences) - 100} more differences")
                    queue_log_message(f"Comparison complete: {len(differences)} differences found")
            queue_progress_update(90, "Generating reports")
            self.report_generator.generate_report(self.assets, self.analyzer.segments, self.analyzer.rom_info)
            queue_log_message(f"Generated extraction report at {os.path.join(output_dir, 'reports', 'extraction_report.txt')}")
            queue_log_message(f"Found {len(self.assets)} assets:")
            for asset in self.assets[:100]:
                msg = f"{asset['type'].upper()} at Offset: 0x{asset['offset']:08x}, Length: {f'0x{asset['length']:08x}' if 'length' in asset else 'unknown'}"
                queue_log_message(msg)
            if len(self.assets) > 100:
                queue_log_message(f"...and {len(self.assets) - 100} more assets")
            queue_progress_update(100, "Analysis complete")
            elapsed = time.time() - self.start_time
            queue_log_message(f"Analysis completed in {elapsed:.2f} seconds")
            queue_messagebox("Success", f"Analysis completed in {elapsed:.2f} seconds. {len(self.assets)} assets extracted.")
            self.root.after(0, lambda: self.preview_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.rebuild_button.config(state=tk.NORMAL))
        except Exception as e:
            if self.stop_event.is_set() or self.cancel_event.is_set():
                queue_log_message("Analysis cancelled or interrupted")
                queue_progress_update(0, "Analysis cancelled")
            else:
                error_msg = f"Analysis failed: {e}"
                self.logger.error(error_msg, exc_info=True)
                queue_log_message(f"Error: {e}")
                queue_progress_update(0, "Analysis failed")
                queue_messagebox("Error", error_msg, error=True)
        finally:
            self.root.after(0, self.cleanup)

    def cleanup(self):
        self.logger.debug("Cleaning up analysis resources")
        try:
            self.run_button.config(state=tk.NORMAL)
            self.pause_button.config(state=tk.DISABLED)
            self.cancel_button.config(state=tk.DISABLED)
            self.cancel_event = None
            self.pause_event = None
            self.start_time = None
            if self.analyzer and os.path.exists(self.analyzer.temp_asset_file):
                self.logger.debug("Removing temp_assets.json")
                try:
                    os.remove(self.analyzer.temp_asset_file)
                except Exception as e:
                    self.logger.error(f"Failed to remove temp_assets.json: {e}")
            self.analyzer = None
            self.report_generator = None
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
        self.logger.debug("Cleanup complete")

    def pause_analysis(self):
        if self.pause_event and not self.pause_event.is_set():
            self.pause_event.set()
            self.pause_button.config(text="Resume", command=self.resume_analysis)
            self.log_message("Analysis paused")
            self.update_progress(self.progress['value'], "Paused")

    def resume_analysis(self):
        if self.pause_event and self.pause_event.is_set():
            self.pause_event.clear()
            self.pause_button.config(text="Pause", command=self.pause_analysis)
            self.log_message("Resuming analysis...")
            self.update_progress(self.progress['value'], "Resuming analysis")

    def cancel_analysis(self):
        if self.cancel_event:
            self.cancel_event.set()
            self.stop_event.set()
            self.log_message("Cancelling analysis...")
            self.update_progress(self.progress['value'], "Cancelling analysis")

    def on_asset_select(self, event):
        selection = self.asset_list.selection()
        if selection:
            item = self.asset_list.item(selection[0])
            asset_type = item['values'][0]
            offset = int(item['values'][1], 16)
            self.update_preview(asset_type, offset)

    def update_preview(self, asset_type, offset):
        try:
            if not self.analyzer:
                self.log_message("No analyzer available for preview")
                return
            if asset_type in ['texture_ci4', 'texture_ci8', 'texture_rgba16']:
                img_data = self.analyzer.get_image_data(offset, asset_type)
                if img_data:
                    img = Image.frombytes('RGBA', (img_data['width'], img_data['height']), img_data['data'])
                    photo = ImageTk.PhotoImage(img)
                    if hasattr(self, 'preview_label'):
                        self.preview_label.destroy()
                    self.preview_label = ttk.Label(self.root, image=photo)
                    self.preview_label.image = photo
                    self.preview_label.grid(row=12, column=0, sticky=(tk.W, tk.E))
            elif asset_type == 'model':
                model_data = self.analyzer.get_model_data(offset)
                if model_data:
                    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
                    glBegin(GL_TRIANGLES)
                    for triangle in model_data['triangles']:
                        for idx in triangle:
                            vertex = model_data['vertices'][idx]
                            glVertex3fv(vertex)
                    glEnd()
                    pygame.display.flip()
        except Exception as e:
            self.logger.error(f"Preview failed: {e}")
            self.log_message(f"Error previewing asset: {e}")

    def preview_asset(self):
        selection = self.asset_list.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select an asset to preview")
            return
        item = self.asset_list.item(selection[0])
        asset_type = item['values'][0]
        offset = int(item['values'][1], 16)
        self.update_preview(asset_type, offset)

    def rebuild_rom(self):
        try:
            if not self.analyzer:
                self.log_message("No analyzer available for ROM rebuild")
                return
            output_rom = os.path.join(self.output_dir.get(), "rebuilt_rom.z64")
            self.analyzer.rebuild_rom(output_rom)
            self.log_message(f"Rebuilt ROM saved to {output_rom}")
            self.root.after(0, lambda: messagebox.showinfo("Success", f"ROM rebuilt successfully: {output_rom}"))
        except Exception as e:
            self.logger.error(f"ROM rebuild failed: {e}")
            self.log_message(f"Error rebuilding ROM: {e}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"Error rebuilding ROM: {e}"))

    def mainloop(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.logger.info("Application interrupted by user")
            self.stop()
        except Exception as e:
            self.logger.error(f"Main loop error: {e}")
        finally:
            self.stop()

    def stop(self):
        if self.is_shutting_down:
            return
        self.is_shutting_down = True
        self.logger.debug("Stopping analysis")
        self.stop_event.set()
        if hasattr(self, 'analyzer') and self.analyzer:
            self.logger.debug("Terminating RomAnalyzer resources")
            self.analyzer = None
        if hasattr(self, 'log_text_handler'):
            try:
                self.log_text_handler.close()
                self.logger.removeHandler(self.log_text_handler)
            except Exception as e:
                self.logger.error(f"Failed to close TextWidgetHandler: {e}")
        try:
            self.update_progress(0, "Analysis stopped")
        except Exception as e:
            self.logger.error(f"Error updating progress during stop: {e}")
