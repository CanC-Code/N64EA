import logging
import tkinter as tk
import queue
import threading
import time

class TextWidgetHandler(logging.Handler):
    def __init__(self, text_widget, root):
        super().__init__()
        self.text_widget = text_widget
        self.root = root
        self.queue = queue.Queue()
        self.running = True
        self.lock = threading.Lock()
        self.text_widget.config(state='disabled')
        self._start_queue_processor()

    def emit(self, record):
        try:
            msg = self.format(record)
            self.queue.put(msg)
        except Exception as e:
            print(f"Error in TextWidgetHandler emit: {e}")

    def _start_queue_processor(self):
        def process_queue():
            while self.running:
                try:
                    msg = self.queue.get_nowait()
                    self._update_text_widget(msg)
                except queue.Empty:
                    time.sleep(0.1)
                except Exception as e:
                    print(f"Error processing queue: {e}")
            print("Queue processor stopped")

        threading.Thread(target=process_queue, daemon=True).start()

    def _update_text_widget(self, msg):
        try:
            with self.lock:
                self.text_widget.config(state='normal')
                self.text_widget.insert(tk.END, msg + '\n')
                self.text_widget.see(tk.END)
                self.text_widget.config(state='disabled')
                self.root.update_idletasks()
        except tk.TclError:
            pass
        except Exception as e:
            print(f"Error updating text widget: {e}")

    def close(self):
        self.running = False
        super().close()
        print("TextWidgetHandler closed")
