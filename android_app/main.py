import json
import asyncio

import flet as ft

from tunnel_client import TunnelClient

DEFAULT_CONFIG = """{
  "mode": "n-1",
  "dns_ips": [],
  "send_domain": "",
  "fake_send_ip": "",
  "fake_send_port": 443,
  "h_in_address": "127.0.0.1:10443",
  "max_domain_len": 99,
  "max_sub_len": 63,
  "retries": 1,
  "send_sock_numbers": 64,
  "my_public_ip": "ezping",
  "send_query_type_int": 1,
  "info_encryption_pass": ""
}"""

CONFIG_STORAGE_KEY = "qs_tunnel_config"

MAX_LOG_LINES = 200


async def main(page: ft.Page):
    page.title = "QS-Tunnel"
    page.theme_mode = ft.ThemeMode.DARK
    page.padding = 20
    page.scroll = ft.ScrollMode.AUTO

    client: TunnelClient | None = None
    client_task: asyncio.Task | None = None

    # --- Log output ---
    log_column = ft.Column(spacing=2, scroll=ft.ScrollMode.AUTO)
    log_container = ft.Container(
        content=log_column,
        height=200,
        border=ft.border.all(1, ft.Colors.GREY_700),
        border_radius=8,
        padding=10,
        bgcolor="#0d1117",
    )

    def add_log(msg: str):
        log_column.controls.append(
            ft.Text(msg, size=12, color=ft.Colors.GREEN_200, selectable=True)
        )
        if len(log_column.controls) > MAX_LOG_LINES:
            log_column.controls.pop(0)
        try:
            page.update()
        except Exception:
            pass

    # --- Status ---
    status_text = ft.Text("● Stopped", size=14, color=ft.Colors.RED_400, weight=ft.FontWeight.BOLD)

    # --- Config editor ---
    saved_config = await page.client_storage.get_async(CONFIG_STORAGE_KEY)
    if saved_config is None:
        saved_config = DEFAULT_CONFIG

    config_editor = ft.TextField(
        value=saved_config,
        multiline=True,
        min_lines=10,
        max_lines=18,
        text_size=12,
        border_color=ft.Colors.BLUE_GREY_700,
        focused_border_color=ft.Colors.BLUE_400,
        content_padding=ft.padding.all(12),
    )

    config_status = ft.Text("", size=12)

    async def save_config(e):
        try:
            json.loads(config_editor.value)
            await page.client_storage.set_async(CONFIG_STORAGE_KEY, config_editor.value)
            config_status.value = "✓ Saved"
            config_status.color = ft.Colors.GREEN_400
        except json.JSONDecodeError as ex:
            config_status.value = f"✗ Invalid JSON: {ex}"
            config_status.color = ft.Colors.RED_400
        page.update()

    async def reset_config(e):
        config_editor.value = DEFAULT_CONFIG
        await page.client_storage.set_async(CONFIG_STORAGE_KEY, DEFAULT_CONFIG)
        config_status.value = "✓ Reset to default"
        config_status.color = ft.Colors.BLUE_400
        page.update()

    # --- Toggle ---
    tunnel_switch = ft.Switch(
        label="Connect",
        value=False,
        active_color=ft.Colors.GREEN_400,
        label_style=ft.TextStyle(size=16, weight=ft.FontWeight.W_500),
    )

    async def toggle_tunnel(e):
        nonlocal client, client_task

        if tunnel_switch.value:
            # --- Start ---
            try:
                config = json.loads(config_editor.value)
            except json.JSONDecodeError as ex:
                add_log(f"Invalid config: {ex}")
                tunnel_switch.value = False
                page.update()
                return

            client = TunnelClient(config, log_callback=add_log)

            status_text.value = "● Starting..."
            status_text.color = ft.Colors.YELLOW_400
            config_editor.read_only = True
            page.update()

            async def run_client():
                nonlocal client
                try:
                    await client.start()
                except asyncio.CancelledError:
                    pass
                except Exception as ex:
                    add_log(f"Error: {ex}")
                finally:
                    if tunnel_switch.value:
                        tunnel_switch.value = False
                    status_text.value = "● Stopped"
                    status_text.color = ft.Colors.RED_400
                    config_editor.read_only = False
                    client = None
                    try:
                        page.update()
                    except Exception:
                        pass

            client_task = page.run_task(run_client)

            # Allow a moment for startup
            await asyncio.sleep(0.1)
            if client and client.is_running:
                status_text.value = "● Running"
                status_text.color = ft.Colors.GREEN_400
            page.update()

        else:
            # --- Stop ---
            if client:
                status_text.value = "● Stopping..."
                status_text.color = ft.Colors.YELLOW_400
                page.update()

                await client.stop()
                client = None

            if client_task:
                client_task.cancel()
                client_task = None

            status_text.value = "● Stopped"
            status_text.color = ft.Colors.RED_400
            config_editor.read_only = False
            page.update()

    tunnel_switch.on_change = toggle_tunnel

    # --- Clear logs ---
    async def clear_logs(e):
        log_column.controls.clear()
        page.update()

    # --- Build UI ---
    page.add(
        # Header
        ft.Container(
            content=ft.Column(
                [
                    ft.Text("QS-Tunnel", size=28, weight=ft.FontWeight.BOLD,
                            color=ft.Colors.BLUE_200),
                    ft.Text("DNS Tunnel Client", size=14, color=ft.Colors.BLUE_400),
                ],
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                spacing=2,
            ),
            alignment=ft.alignment.center,
            padding=ft.padding.only(bottom=10),
        ),

        # Info card
        ft.Card(
            content=ft.Container(
                content=ft.Column(
                    [
                        ft.Row(
                            [
                                ft.Icon(ft.Icons.PERSON, color=ft.Colors.BLUE_200, size=20),
                                ft.Text("@patterniha", size=16, weight=ft.FontWeight.BOLD,
                                         color=ft.Colors.BLUE_200, selectable=True),
                            ],
                            spacing=8,
                        ),
                        ft.Divider(height=1, color=ft.Colors.GREY_700),
                        ft.Text("Donate USDT (BEP20):", size=12, color=ft.Colors.GREY_400),
                        ft.Text(
                            "0x76a768B53Ca77B43086946315f0BDF21156bF424",
                            size=11,
                            color=ft.Colors.AMBER_200,
                            selectable=True,
                        ),
                    ],
                    spacing=6,
                ),
                padding=15,
            ),
            color="#1a1a2e",
        ),

        ft.Divider(height=15, color=ft.Colors.TRANSPARENT),

        # Toggle section
        ft.Card(
            content=ft.Container(
                content=ft.Row(
                    [tunnel_switch, status_text],
                    alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
                ),
                padding=15,
            ),
            color="#1a1a2e",
        ),

        ft.Divider(height=15, color=ft.Colors.TRANSPARENT),

        # Config section
        ft.Text("Configuration", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_200),
        config_editor,
        ft.Row(
            [
                ft.ElevatedButton("Save", icon=ft.Icons.SAVE, on_click=save_config),
                ft.OutlinedButton("Reset", icon=ft.Icons.RESTORE, on_click=reset_config),
                config_status,
            ],
            spacing=10,
        ),

        ft.Divider(height=15, color=ft.Colors.TRANSPARENT),

        # Logs section
        ft.Row(
            [
                ft.Text("Logs", size=16, weight=ft.FontWeight.BOLD, color=ft.Colors.BLUE_200),
                ft.IconButton(ft.Icons.DELETE_OUTLINE, on_click=clear_logs, tooltip="Clear logs",
                              icon_color=ft.Colors.GREY_400, icon_size=18),
            ],
            alignment=ft.MainAxisAlignment.SPACE_BETWEEN,
        ),
        log_container,
    )


ft.app(target=main)
