import flet as ft

# --- 🎨 THEME COLORS ---
APP_TITLE = "LOCKON: THE ORBITAL STRIKE"
COLOR_BG_APP = "#0D1117"
COLOR_BG_PANEL = "#161B22"
COLOR_BG_INPUT = "#090C10"
COLOR_BORDER = "#30363D"
COLOR_ACCENT = "#F85149"
COLOR_PRIMARY = "#238636"
COLOR_TEXT_MAIN = "#C9D1D9"
COLOR_TEXT_DIM = "#8B949E"
COLOR_TERM_BG = "#090C10"
COLOR_C2_BG = "#000000"
COLOR_C2_TEXT = "#00FF00" 
COLOR_SEV_CRITICAL = "#FF7B72"
COLOR_SEV_HIGH = "#D2A8FF"
COLOR_SEV_MEDIUM = "#D29922"
COLOR_SEV_LOW = "#3FB950"
COLOR_SEV_INFO = "#58A6FF"

# --- Centralized Surface Colors (previously per-tab) ---
COLOR_SURFACE = "#161B22"
COLOR_INPUT_FIELD = "#0D1117"
COLOR_BORDER_SUBTLE = "#30363D"
COLOR_ACCENT_PRIMARY = "#58A6FF"
COLOR_ACCENT_WARN = "#D29922"
COLOR_ACCENT_DANGER = "#FF7B72"

# --- FONTS ---
FONTS = {
    "Hacker": "Consolas, 'Courier New', monospace",
    "UI": "Segoe UI, Roboto, sans-serif"
}

def apply_theme(page: ft.Page):
    page.title = APP_TITLE
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = COLOR_BG_APP
    page.window.width = 1600
    page.window.height = 900
    page.padding = 0
    page.fonts = FONTS
    
    page.theme = ft.Theme(
        font_family="UI",
        scrollbar_theme=ft.ScrollbarTheme(
            thumb_color={
                ft.ControlState.DEFAULT: "#30363D",
                ft.ControlState.HOVERED: "#484F58",
            },
            thickness=8,
            radius=4,
            interactive=True
        )
    )

