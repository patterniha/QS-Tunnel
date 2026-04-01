"""QS Tunnel Client - Android App

Simple Kivy-based GUI to run, stop, and configure the QS Tunnel client.
"""

import asyncio
import json
import os
import sys
import threading

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.utils import platform

if platform == "android":
    from android.permissions import Permission, request_permissions

    request_permissions(
        [
            Permission.INTERNET,
            Permission.ACCESS_NETWORK_STATE,
            Permission.WAKE_LOCK,
        ]
    )


class QSTunnelApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.tunnel_thread = None
        self.tunnel_loop = None
        self.tunnel_namespace = None
        self.running = False
        self.toggle_btn = None
        self.status_label = None
        self.config_input = None
        self.log_output = None
        self._stdout_backup = None

    def get_script_dir(self):
        return os.path.dirname(os.path.abspath(__file__))

    def get_config_path(self):
        return os.path.join(self.get_script_dir(), "config_client.json")

    def build(self):
        self.title = "QS Tunnel Client"

        root = BoxLayout(orientation="vertical", padding=10, spacing=5)

        self.status_label = Label(
            text="Status: Stopped",
            size_hint_y=None,
            height=40,
            color=(1, 0.3, 0.3, 1),
        )
        root.add_widget(self.status_label)

        self.toggle_btn = Button(
            text="Start Tunnel",
            size_hint_y=None,
            height=50,
            background_color=(0.2, 0.7, 0.2, 1),
        )
        self.toggle_btn.bind(on_press=self.toggle)
        root.add_widget(self.toggle_btn)

        root.add_widget(
            Label(text="Configuration (JSON):", size_hint_y=None, height=30)
        )

        self.config_input = TextInput(
            text=self._load_config_text(),
            multiline=True,
            font_size="14sp",
            size_hint_y=0.4,
        )
        root.add_widget(self.config_input)

        save_btn = Button(text="Save Config", size_hint_y=None, height=50)
        save_btn.bind(on_press=self.save_config)
        root.add_widget(save_btn)

        root.add_widget(Label(text="Log:", size_hint_y=None, height=30))

        self.log_output = TextInput(
            text="",
            multiline=True,
            readonly=True,
            size_hint_y=0.3,
            font_size="12sp",
        )
        root.add_widget(self.log_output)

        return root

    def _get_default_config(self):
        return {
            "mode": "n-1",
            "dns_ips": [],
            "send_domain": "",
            "fake_send_ip": "",
            "fake_send_port": 443,
            "h_in_address": "127.0.0.1:10443",
            "max_domain_len": 99,
            "max_sub_len": 63,
            "retries": 1,
            "packets_send_interval": 0.001,
            "send_sock_numbers": 512,
            "my_public_ip": "ezping",
        }

    def _load_config_text(self):
        try:
            with open(self.get_config_path(), "r") as f:
                return f.read()
        except FileNotFoundError:
            return json.dumps(self._get_default_config(), indent=2)

    def save_config(self, *_args):
        try:
            json.loads(self.config_input.text)
            with open(self.get_config_path(), "w") as f:
                f.write(self.config_input.text)
            self._log("Config saved.")
        except json.JSONDecodeError as e:
            self._log(f"Invalid JSON: {e}")

    def toggle(self, *_args):
        if self.running:
            self.stop_tunnel()
        else:
            self.start_tunnel()

    def start_tunnel(self):
        if self.running:
            return

        self.save_config()
        self.running = True
        self.toggle_btn.text = "Stop Tunnel"
        self.toggle_btn.background_color = (0.8, 0.2, 0.2, 1)
        self.status_label.text = "Status: Running"
        self.status_label.color = (0.3, 1, 0.3, 1)
        self._log("Starting tunnel...")

        self.tunnel_thread = threading.Thread(target=self._run_tunnel, daemon=True)
        self.tunnel_thread.start()

    def stop_tunnel(self):
        if self.tunnel_loop and self.tunnel_loop.is_running():
            for task in asyncio.all_tasks(self.tunnel_loop):
                self.tunnel_loop.call_soon_threadsafe(task.cancel)
            self.tunnel_loop.call_soon_threadsafe(self.tunnel_loop.stop)

        self._close_tunnel_sockets()

        self.running = False
        self._update_stopped_ui()
        self._log("Tunnel stopped.")

    def _close_tunnel_sockets(self):
        ns = self.tunnel_namespace
        if ns is None:
            return
        for sock in ns.get("send_sock_list", []):
            try:
                sock.close()
            except Exception:
                pass
        for name in ("h_inbound_socket", "wan_main_socket"):
            sock = ns.get(name)
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _run_tunnel(self):
        script_dir = self.get_script_dir()
        script_path = os.path.join(script_dir, "main_client.py")

        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)

        self.tunnel_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.tunnel_loop)

        old_argv = sys.argv[:]
        sys.argv = [script_path]

        self._stdout_backup = sys.stdout
        sys.stdout = _ThreadFilteredWriter(
            threading.current_thread(), self._schedule_log, sys.stdout
        )

        try:
            with open(script_path, "r") as f:
                code = f.read()

            code = code.rstrip()
            suffix = "asyncio.run(main())"
            if code.endswith(suffix):
                code = code[: -len(suffix)]

            namespace = {"__name__": "__main__", "__file__": script_path}
            exec(compile(code, script_path, "exec"), namespace)  # noqa: S102
            self.tunnel_namespace = namespace

            self._schedule_log("Tunnel started.")
            self.tunnel_loop.run_until_complete(namespace["main"]())
        except (SystemExit, KeyboardInterrupt):
            pass
        except Exception as e:
            self._schedule_log(f"Tunnel error: {e}")
        finally:
            sys.argv = old_argv
            sys.stdout = self._stdout_backup
            self._stdout_backup = None

            try:
                pending = asyncio.all_tasks(self.tunnel_loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self.tunnel_loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
            except Exception:
                pass
            try:
                self.tunnel_loop.close()
            except Exception:
                pass
            self.tunnel_loop = None
            self.tunnel_namespace = None
            Clock.schedule_once(lambda _dt: self._on_tunnel_stopped(), 0)

    def _on_tunnel_stopped(self):
        self.running = False
        self._update_stopped_ui()

    def _update_stopped_ui(self):
        self.toggle_btn.text = "Start Tunnel"
        self.toggle_btn.background_color = (0.2, 0.7, 0.2, 1)
        self.status_label.text = "Status: Stopped"
        self.status_label.color = (1, 0.3, 0.3, 1)

    def _schedule_log(self, text):
        Clock.schedule_once(lambda _dt: self._log(text), 0)

    def _log(self, text):
        if self.log_output is None:
            return
        self.log_output.text += text + "\n"
        lines = self.log_output.text.split("\n")
        if len(lines) > 200:
            self.log_output.text = "\n".join(lines[-200:])

    def on_stop(self):
        if self.running:
            self.stop_tunnel()


class _ThreadFilteredWriter:
    """Redirect stdout only for a specific thread to a callback."""

    def __init__(self, target_thread, callback, original):
        self.target_thread = target_thread
        self.callback = callback
        self.original = original

    def write(self, text):
        if threading.current_thread() == self.target_thread and text.strip():
            self.callback(text.strip())
        return self.original.write(text)

    def flush(self):
        return self.original.flush()

    def fileno(self):
        return self.original.fileno()


if __name__ == "__main__":
    QSTunnelApp().run()
