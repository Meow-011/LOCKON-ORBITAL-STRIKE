import flet as ft
import flet.canvas as cv
import math
from gui.theme import *

class GraphNode(ft.Container):
    def __init__(self, node_id, label, icon, color, x, y, on_click=None):
        super().__init__()
        self.node_id = node_id
        self.left = x
        self.top = y
        self.on_click = on_click
        
        self.content = ft.Column([
            ft.Container(
                content=ft.Icon(icon, color="black", size=20),
                width=40, height=40,
                bgcolor=color,
                border_radius=20, # Circle
                alignment=ft.alignment.center,
                border=ft.border.all(2, "white"),
                shadow=ft.BoxShadow(spread_radius=1, blur_radius=10, color=color, offset=ft.Offset(0,0)),
            ),
            ft.Container(
                content=ft.Text(label, size=10, color="white", font_family="Consolas", weight="bold", no_wrap=True),
                bgcolor="black",
                padding=ft.padding.symmetric(horizontal=5, vertical=2),
                border_radius=5,
                opacity=0.8
            )
        ], spacing=2, horizontal_alignment=ft.CrossAxisAlignment.CENTER)

class GraphTab:
    def __init__(self, page):
        self.page = page
        self.nodes = {} # id -> node_data
        self.edges = [] # (parent_id, child_id)
        
        # Interactive State
        self.offset_x = 0
        self.offset_y = 0
        self.last_offset_x = 0
        self.last_offset_y = 0
        self.scale = 1.0
        
        # Canvas for drawing lines
        self.canvas = cv.Canvas(expand=True)
        
        # Stack for placing nodes on top of lines
        self.node_stack = ft.Stack(expand=True)
        
        # Inner Stack (The Content to Move/Zoom)
        self.inner_stack = ft.Stack([
            # Grid Background (Infinite-ish illusion)
            ft.Container(bgcolor="#0f0f0f", expand=True), 
            # Lines Layer
            self.canvas,
            # Nodes Layer
            self.node_stack
        ], expand=True)
        
        # Transform Container (Applies the Matrix)
        # Note: We use margin/padding or explicit left/top for Panning if Offset is percentage based?
        # Flet Offset is (x, y) where 1.0 = 100% of size. 
        # Better to use `left` and `top` properties in a Stack, OR use proper Matrix transform if available.
        # For simplicity and performance, placing inside a Stack and updating `left`/`top` is reliable.
        # BUT `inner_stack` needs to be larger than view? No, it's the view itself.
        # Let's use `ft.TransparentPointer` if we needed pass through, but here we want to catch gestures.
        
        # Alternative: Use `transform_offset` (pixels) is not standard Flet yet (offset is ratio).
        # We will use a wrapper Stack and position the `inner_stack` absolutely within it.
        
        self.movable_content = ft.Container(
            content=self.inner_stack,
            expand=True,
            scale=ft.Scale(1.0),
            offset=ft.Offset(0, 0), # This is ratio! 0.1 = 10% width. Not good for pixel panning.
            # Using left/top in a stack is better for pixel precision.
        )
        
        # Wait, to use pixel precision panning, `movable_content` should be in a Stack and we update its left/top.
        # Let's redefine.
        
        self.content_layer = ft.Stack([
             ft.Container(
                 content=self.inner_stack,
                 ref=ft.Ref(), # Handle ref if needed
             )
        ], expand=True)

        # Actually, let's try the cleanest Flet way: 
        # Scale works fine.
        # For Panning: `offset` is Ratio. If we want Pixel panning, we usually need to know the Size.
        # OR we use `left` / `top` of a known size container.
        # Let's use `margin`? No.
        
        # Let's stick to `offset` but converting pixels to approx ratio is hard without knowing width.
        # RE-EVALUATION: simple `left` / `top` modification is best.
        
        self.graph_content = ft.Container(
            content=self.inner_stack,
            width=2000, height=2000, # Large virtual canvas
            left=0, top=0,
            scale=ft.Scale(self.scale),
            animate_scale=ft.Animation(200, "easeOut"),
            animate_position=ft.Animation(50, "linear") # Smooth drag
        )

        self.gesture_detector = ft.GestureDetector(
            content=ft.Stack([self.graph_content], expand=True),
            on_pan_update=self._on_pan_update,
            on_scroll=self._on_scroll,
            expand=True,
            drag_interval=10
        )
        
        self.graph_container = ft.Container(
            content=self.gesture_detector,
            expand=True,
            border=ft.border.all(1, COLOR_BORDER),
            clip_behavior=ft.ClipBehavior.HARD_EDGE,
            bgcolor="#0f0f0f"
        )
        
        # Initialize Kill Chain Backbone (The Spine)
        # 1. Attacker (Root)
        self.add_node("ROOT", "ATTACKER", ft.Icons.LAPTOP, "#00b4d8", 50, 300)
        
        # 2. Reconnaissance
        self._add_backbone_node("RECON", "RECONNAISSANCE", ft.Icons.RADAR, "#00b4d8", 250, 300, "ROOT")
        
        # 3. Weaponization
        self._add_backbone_node("WEAPON", "WEAPONIZATION", ft.Icons.BUILD, "#ff9100", 450, 300, "RECON")
        
        # 4. Exploitation
        self._add_backbone_node("EXPLOIT", "EXPLOITATION", ft.Icons.FLASH_ON, "#ff0000", 650, 300, "WEAPON")
        
        # 5. Actions on Objective
        self._add_backbone_node("ACTION", "ACTIONS", ft.Icons.FLAG, "#00ff00", 850, 300, "EXPLOIT")

    def _add_backbone_node(self, node_id, label, icon, color, x, y, parent_id):
         # Helper to add spine nodes without triggering auto-layout for them (fixed position)
         self.nodes[node_id] = {'x': x, 'y': y, 'color': color}
         node_control = GraphNode(node_id, label, icon, color, x, y)
         self.node_stack.controls.append(node_control)
         self.edges.append((parent_id, node_id))
         self.redraw_lines()

    def _on_pan_update(self, e: ft.DragUpdateEvent):
        # Update position
        self.graph_content.left = (self.graph_content.left or 0) + e.delta_x
        self.graph_content.top = (self.graph_content.top or 0) + e.delta_y
        self.graph_content.update()

    def _on_scroll(self, e: ft.ScrollEvent):
        # Zoom (Scroll Y)
        if e.scroll_delta_y < 0:
            self.scale = min(self.scale + 0.1, 3.0)
        else:
            self.scale = max(self.scale - 0.1, 0.5)
            
        self.graph_content.scale = ft.Scale(self.scale)
        self.graph_content.update()

    def add_node(self, node_id, label, icon=ft.Icons.CIRCLE, color="white", x=0, y=0, parent_id=None):
        """
        Add a node to the graph. If parent_id is provided, automatically calculates layout.
        """
        # Dynamic Layout Logic (Simple Tree)
        if parent_id and parent_id in self.nodes:
            parent = self.nodes[parent_id]
            level_width = 150
            sibling_count = len([e for e in self.edges if e[0] == parent_id])
            
            # Position relative to parent
            x = parent['x'] + level_width
            # Fan out y based on siblings
            base_y = parent['y']
            offset = (sibling_count * 60) - 30 # Simple fan out
            y = base_y + offset
            
            # Avoid collision (Very basic)
            while any(n['x'] == x and abs(n['y'] - y) < 40 for n in self.nodes.values()):
                y += 50
                
            self.edges.append((parent_id, node_id))
        
        # Store Data
        self.nodes[node_id] = {'x': x, 'y': y, 'color': color}
        
        # Create Control
        node_control = GraphNode(node_id, label, icon, color, x, y)
        self.node_stack.controls.append(node_control)
        
        # Redraw Lines
        self.redraw_lines()
        
        # Hide empty overlay
        if hasattr(self, 'empty_overlay') and self.empty_overlay.visible:
            self.empty_overlay.visible = False
        
        try:
            self.page.update()
        except Exception: pass

    def redraw_lines(self):
        self.canvas.shapes.clear()
        
        for p_id, c_id in self.edges:
            p = self.nodes[p_id]
            c = self.nodes[c_id]
            
            # Center of nodes (approx +20 offset for 40x40 node)
            x1, y1 = p['x'] + 20, p['y'] + 20
            x2, y2 = c['x'] + 20, c['y'] + 20
            
            # Bezier Control Points (S-Curve)
            cp1_x = x1 + (x2 - x1) / 2
            cp1_y = y1
            cp2_x = x1 + (x2 - x1) / 2
            cp2_y = y2
            
            self.canvas.shapes.append(
                cv.Path(
                    [
                        cv.Path.MoveTo(x1, y1),
                        cv.Path.CubicTo(cp1_x, cp1_y, cp2_x, cp2_y, x2, y2)
                    ],
                    paint=ft.Paint(
                        stroke_width=2,
                        color=ft.Colors.with_opacity(0.5, p['color']),
                        style=ft.PaintingStyle.STROKE
                    )
                )
            )

    def get_content(self):
        # Empty state overlay — hides when nodes are added
        self.empty_overlay = ft.Container(
            content=ft.Column([
                ft.Icon(ft.Icons.POLYLINE_OUTLINED, size=48, color=COLOR_TEXT_DIM),
                ft.Text("Waiting for scan data to visualize attack paths...", size=14, color=COLOR_TEXT_DIM, weight="bold"),
                ft.Text("Findings will appear as nodes connected to kill chain phases.", size=11, color=COLOR_TEXT_DIM),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=8),
            alignment=ft.alignment.center,
            expand=True,
            bgcolor=ft.Colors.with_opacity(0.85, COLOR_BG_APP),
            visible=True  # Show by default
        )
        return ft.Column([
            ft.Row([
                ft.Icon(ft.Icons.POLYLINE, color=COLOR_SEV_CRITICAL),
                ft.Text("BLOODHOUND ATTACK GRAPH (Visual Matrix)", font_family="Consolas", size=16, color=COLOR_SEV_CRITICAL),
                ft.Container(expand=True),
                ft.Text("Drag to Pan | Scroll to Zoom", color=COLOR_TEXT_DIM, size=10),
                ft.IconButton(ft.Icons.ZOOM_IN, on_click=lambda e: self.zoom(0.1), tooltip="Zoom In", icon_size=16),
                ft.IconButton(ft.Icons.ZOOM_OUT, on_click=lambda e: self.zoom(-0.1), tooltip="Zoom Out", icon_size=16),
                ft.IconButton(ft.Icons.CENTER_FOCUS_STRONG, on_click=self.reset_view, tooltip="Reset View", icon_size=16),
            ]),
            ft.Divider(color="#333333", height=1),
            ft.Stack([self.graph_container, self.empty_overlay], expand=True)
        ], expand=True, spacing=0)

    def zoom(self, delta):
        self.scale = max(0.5, min(3.0, self.scale + delta))
        self.graph_content.scale = ft.Scale(self.scale)
        self.graph_content.update()

    def reset_view(self, e):
        self.scale = 1.0
        self.graph_content.scale = ft.Scale(1.0)
        self.graph_content.left = 0
        self.graph_content.top = 0
        self.graph_content.update()

    # --- [PHASE 50] DYNAMIC DATA SYNC ---
    def update_graph_from_data(self):
        from core.scanner import scanner
        from core.c2_manager import c2_manager
        
        # 1. Map Findings to "VULN" Nodes
        # We hook them to "RECON" (if info) or "EXPLOIT" (if critical)
        # For simplicity, we hook criticals to WEAPON -> EXPLOIT
        
        # Clear old dynamic links? (Complex to track, strictly adding for now)
        # In a real app, we'd diff. Here we just add if not exists.
        
        finding_nodes = {}
        
        for i, f in enumerate(scanner.all_findings):
            f_id = f"FINDING_{i}"
            if f_id in self.nodes: continue
            
            label = f['type']
            severity = f.get('severity', 'Info')
            
            parent = "RECON"
            icon = ft.Icons.SEARCH
            color = "#00b4d8"
            
            if severity in ["Critical", "High"]:
                parent = "WEAPON"
                icon = ft.Icons.BUG_REPORT
                color = "#ff0000"
            elif severity == "Medium":
                parent = "WEAPON"
                icon = ft.Icons.WARNING
                color = "#ff9100"
                
            self.add_node(f_id, label, icon, color, parent_id=parent)
            finding_nodes[f_id] = f # Store ref
            
        # 2. Map C2 Sessions to "SHELL" Nodes
        # these hook to "EXPLOIT" or specific Finding if we tracked origin
        for s in c2_manager.sessions:
            s_id = f"SESSION_{s['id']}"
            if s_id in self.nodes: continue
            
            label = f"SHELL {s['id']}\n{s['ip']}"
            
            # Try to guess origin, otherwise hook to EXPLOIT
            parent = "EXPLOIT"
            
            self.add_node(s_id, label, ft.Icons.TERMINAL, "#39FF14", parent_id=parent)
            
            # Loot from this session?
            # Hook "LOOT" nodes to Session
            
    def auto_refresh(self):
        self.update_graph_from_data()
        self.page.update()
