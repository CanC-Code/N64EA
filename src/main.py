import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import os
import glob
from PIL import Image, ImageTk
import logging
import pygame
from OpenGL.GL import *
from OpenGL.GLU import *
from analysis.rom_analyzer import RomAnalyzer
from analysis.splat_integration import SplatIntegration
from assets.image_decoder import ImageDecoder
from assets.model_parser import ModelParser
from assets.crc_calculator import CRCCalculator
from gui.main_window import MainWindow
from gui.text_handler import TextWidgetHandler
from utils.logging_config import setup_logging
from utils.signal_handler import setup_signal_handler
import re
import psutil

class N64ExtractorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("N64EA - Enhanced N64 Extraction & Analysis")
        self.logger = setup_logging()
        self.logger.info("N64 Extractor App initialized")
        self.rom_path = tk.StringVar(value="No ROM selected")
        self.output_dir = tk.StringVar(value="No output folder selected")
        self.preview_window = None
        self.analyzer = None
        self.splat_integration = None
        self.image_decoder = ImageDecoder()
        self.model_parser = None
        self.current_image = None
        self.assets = []
        self.is_shutting_down = False
        self.process = psutil.Process()
        
        setup_signal_handler(self, self.logger)
        
        self.main_window = MainWindow(self.root)
        self.setup_gui()
        
        self.root.protocol("WM_DELETE_WINDOW", self.stop)
    
    def setup_gui(self):
        frame = self.main_window.root.winfo_children()[0]
        self.preview_button = ttk.Button(frame, text="Open Asset Preview", command=self.open_preview)
        self.preview_button.grid(row=7, column=2, sticky=tk.W)
        
        for widget in frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget.cget("text") == "Browse" and widget.grid_info()['row'] == 1:
                widget.configure(command=self.select_output_dir)
        
        self.main_window.asset_list.bind('<<TreeviewSelect>>', self.on_asset_select)
    
    def select_rom(self):
        rom_file = filedialog.askopenfilename(filetypes=[("N64 ROMs", "*.z64 *.n64 *.v64")])
        if rom_file:
            self.rom_path.set(rom_file)
            self.main_window.rom_path.set(rom_file)
            self.main_window.log_message(f"Selected ROM: {rom_file}")
            try:
                with open(rom_file, 'rb') as f:
                    header = f.read(64)
                game_title = header[32:52].decode('ascii', errors='ignore').strip()
                game_code = header[59:63].decode('ascii', errors='ignore').strip()
                version = header[63]
                self.logger.debug(f"ROM header - Title: '{game_title}', Code: '{game_code}', Version: {version}")
                if not game_title:
                    game_title = "Unknown"
                game_title = re.sub(r'[^a-zA-Z0-9\-_]', '_', game_title.replace(' ', '_'))
                game_title = f"{game_title}_v{version}"
                self.logger.debug(f"Sanitized game title: '{game_title}'")
            except Exception as e:
                self.logger.error(f"Failed to read ROM header: {e}")
                game_title = f"ROM_{os.path.splitext(os.path.basename(rom_file))[0]}"
            default_dir = os.path.join("/home/ubuntu/Desktop/extraction", game_title)
            try:
                os.makedirs(default_dir, exist_ok=True)
                subfolders = ['images', 'audio', 'compressed', 'segments', 'other', 'reports']
                for subfolder in subfolders:
                    os.makedirs(os.path.join(default_dir, subfolder), exist_ok=True)
                self.output_dir.set(default_dir)
                self.main_window.output_dir.set(default_dir)
                self.main_window.log_message(f"Set output folder to: {default_dir}")
                self.main_window.log_message(f"Subfolders created: {', '.join(os.path.join(default_dir, s) for s in subfolders)}")
            except Exception as e:
                self.logger.error(f"Failed to create output directories: {e}")
                self.main_window.log_message(f"Error creating output directories: {e}")
                messagebox.showerror("Error", f"Failed to create output directories: {e}")
                return
            try:
                self.splat_integration = SplatIntegration(rom_file, default_dir)
                self.main_window.splat_integration = self.splat_integration
                self.main_window.log_message(f"Generated rom_config.yaml at {self.splat_integration.yaml_path}")
                self.analyzer = RomAnalyzer(rom_file, default_dir)
                self.model_parser = ModelParser(self.analyzer.rom_data)
                self.logger.info(f"Memory usage after initialization: {self.process.memory_info().rss / 1024**2:.2f} MB")
            except Exception as e:
                self.logger.error(f"Failed to initialize: {e}")
                self.main_window.log_message(f"Error initializing: {e}")
                messagebox.showerror("Error", f"Failed to initialize: {e}")
    
    def select_output_dir(self, default_dir=None):
        initial_dir = os.path.dirname(default_dir) if default_dir else "/home/ubuntu/Desktop/extraction"
        output_dir = filedialog.askdirectory(initialdir=initial_dir, title="Select Output Folder")
        if output_dir:
            try:
                game_title = os.path.basename(default_dir) if default_dir else "Unknown"
                output_dir = os.path.join(output_dir, game_title)
                os.makedirs(output_dir, exist_ok=True)
                subfolders = ['images', 'audio', 'compressed', 'segments', 'other', 'reports']
                for subfolder in subfolders:
                    os.makedirs(os.path.join(output_dir, subfolder), exist_ok=True)
                self.output_dir.set(output_dir)
                self.main_window.output_dir.set(output_dir)
                self.main_window.log_message(f"Set output folder to: {output_dir}")
                self.main_window.log_message(f"Subfolders created: {', '.join(os.path.join(output_dir, s) for s in subfolders)}")
            except Exception as e:
                self.logger.error(f"Failed to create output directories: {e}")
                self.output_dir.set("No output folder selected")
                self.main_window.output_dir.set("No output folder selected")
                self.main_window.log_message(f"Error creating output directories: {e}")
                messagebox.showerror("Error", f"Failed to create output directories: {e}")
        else:
            self.output_dir.set("No output folder selected")
            self.main_window.output_dir.set("No output folder selected")
            self.main_window.log_message("Output folder selection cancelled")
    
    def open_preview(self):
        if not self.analyzer or not os.path.exists(self.output_dir.get()):
            messagebox.showerror("Error", "No assets extracted. Please run analysis first.")
            self.logger.error("Preview attempted but no assets or output directory found")
            return
        
        if self.preview_window and self.preview_window.winfo_exists():
            self.preview_window.lift()
            return
        
        self.preview_window = tk.Toplevel(self.root)
        self.preview_window.title("N64EA - Asset Preview")
        self.preview_window.geometry("600x400")
        self.preview_window.protocol("WM_DELETE_WINDOW", self.close_preview)
        
        tree = ttk.Treeview(self.preview_window, columns=("Type", "Offset", "Length"), show="headings")
        tree.heading("Type", text="Asset Type")
        tree.heading("Offset", text="Offset")
        tree.heading("Length", text="Length")
        tree.grid(row=0, column=0, sticky="nsew")
        
        canvas = tk.Canvas(self.preview_window, width=300, height=300, bg="white")
        canvas.grid(row=0, column=1, sticky="nsew")
        self.canvas = canvas
        
        asset_dir = self.output_dir.get()
        subfolders = ['images', 'audio', 'compressed', 'segments', 'other']
        for subfolder in subfolders:
            subdir_path = os.path.join(asset_dir, subfolder)
            if os.path.exists(subdir_path):
                parent = tree.insert("", "end", text=subfolder, values=(subfolder,))
                for file in glob.glob(os.path.join(subdir_path, '*')):
                    match = re.search(r'0x([0-9a-fA-F]+)', file)
                    offset = int(match.group(1), 16) if match else 0
                    asset_type = {
                        '.png': 'texture_ci4',
                        '.obj': 'model',
                        '.bin': 'vadpcm' if 'audio' in subfolder else 'mio0' if 'compressed' in subfolder else 'unknown'
                    }.get(os.path.splitext(file)[1], 'unknown')
                    tree.insert(parent, "end", text=os.path.basename(file), 
                               values=(asset_type, hex(offset), "unknown"), tags=(file,))
        
        tree.bind("<<TreeviewSelect>>", lambda e: self.preview_asset(tree))
        
        self.preview_window.grid_rowconfigure(0, weight=1)
        self.preview_window.grid_columnconfigure(0, weight=1)
        self.preview_window.grid_columnconfigure(1, weight=1)
        
        self.logger.info("Asset preview window opened")
    
    def close_preview(self):
        if self.preview_window and self.preview_window.winfo_exists():
            self.preview_window.destroy()
            self.preview_window = None
            self.logger.info("Asset preview window closed")
    
    def preview_asset(self, tree):
        selection = tree.selection()
        if not selection:
            return
        
        item = tree.item(selection[0])
        file_path = item['tags'][0] if item['tags'] else None
        asset_type = item['values'][0]
        offset = int(item['values'][1], 16) if item['values'][1] != 'unknown' else 0
        
        if not file_path or not os.path.exists(file_path):
            self.logger.warning(f"Invalid file path for preview: {file_path}")
            return
        
        self.canvas.delete("all")
        
        try:
            if asset_type in ['texture_ci4', 'texture_ci8', 'texture_rgba16']:
                img = Image.open(file_path)
                img = img.resize((300, 300), Image.LANCZOS)
                self.current_image = ImageTk.PhotoImage(img)
                self.canvas.create_image(150, 150, image=self.current_image)
                self.logger.info(f"Previewing texture: {file_path}")
            elif asset_type == 'model':
                if not pygame.get_init():
                    pygame.display.set_mode((300, 300), pygame.OPENGL | pygame.DOUBLEBUF)
                    glClearColor(0.0, 0.0, 0.0, 1.0)
                    glEnable(GL_DEPTH_TEST)
                    gluPerspective(45, 1, 0.1, 50.0)
                    glTranslatef(0.0, 0.0, -5)
                
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
                    buffer = glReadPixels(0, 0, 300, 300, GL_RGBA, GL_UNSIGNED_BYTE)
                    img = Image.frombytes('RGBA', (300, 300), buffer)
                    img = img.transpose(Image.FLIP_TOP_BOTTOM)
                    self.current_image = ImageTk.PhotoImage(img)
                    self.canvas.create_image(150, 150, image=self.current_image)
                    self.logger.info(f"Previewing model: {file_path}")
            else:
                with open(file_path, 'rb') as f:
                    data = f.read(16)
                metadata = f"File: {os.path.basename(file_path)}\nType: {asset_type}\nOffset: {hex(offset)}\nSize: {os.path.getsize(file_path)} bytes\nFirst 16 bytes: {data.hex()}"
                self.canvas.create_text(150, 150, text=metadata, justify="center", font=("Arial", 10))
                self.logger.info(f"Previewing metadata for: {file_path}")
        except Exception as e:
            self.logger.error(f"Failed to preview asset {file_path}: {e}")
            self.canvas.create_text(150, 150, text=f"Error: {e}", font=("Arial", 10))
    
    def on_asset_select(self, event):
        self.main_window.on_asset_select(event)
    
    def stop(self):
        if self.is_shutting_down:
            return
        self.is_shutting_down = True
        self.logger.info("Shutting down N64EA")
        try:
            self.close_preview()
            if self.analyzer:
                self.main_window.cleanup()
            if pygame.get_init():
                pygame.quit()
            self.main_window.stop()
            self.root.quit()
            self.root.destroy()
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
        finally:
            logging.shutdown()

if __name__ == "__main__":
    root = tk.Tk()
    app = N64ExtractorApp(root)
    app.main_window.mainloop()
