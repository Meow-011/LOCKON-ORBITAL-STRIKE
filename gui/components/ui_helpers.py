import flet as ft
from gui.theme import *

def create_input_label(text, icon):
    return ft.Row(
        [
            ft.Icon(icon, size=14, color=COLOR_TEXT_DIM), 
            ft.Text(text, size=11, weight="bold", color=COLOR_TEXT_DIM, font_family="Hacker")
        ], 
        spacing=5
    )

def create_stat_badge(label, value, color):
    return ft.Container(
        padding=ft.padding.symmetric(horizontal=10, vertical=5),
        bgcolor=COLOR_BG_INPUT,
        border=ft.border.all(1, COLOR_BORDER),
        border_radius=4,
        content=ft.Row([
            ft.Container(width=6, height=6, border_radius=3, bgcolor=color), 
            ft.Text(label, size=10, color=COLOR_TEXT_DIM), 
            ft.Text(str(value), size=12, weight="bold", color="white")
        ], spacing=8)
    )
