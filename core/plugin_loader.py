"""
Plugin Loader
Auto-discover and load plugins from the plugins/ directory.
Each plugin must define a class that inherits from LockonPlugin.
"""
import os
import importlib
import importlib.util
import inspect
import traceback


class LockonPlugin:
    """Base class for LOCKON plugins. All plugins must inherit from this."""
    
    # Plugin metadata (override in subclass)
    name = "Unnamed Plugin"
    version = "1.0"
    author = "Unknown"
    description = "No description"
    category = "general"  # e.g., "recon", "exploit", "reporting", "analysis"
    
    def __init__(self, log_callback=None):
        self.log = log_callback or (lambda msg: None)
        self.results = []
    
    async def run(self, target, session=None, findings=None):
        """
        Main plugin entry point.
        
        Args:
            target: Target URL string
            session: aiohttp.ClientSession (optional)
            findings: List of existing findings (optional, for analysis plugins)
        
        Returns:
            List of finding dicts, or None
        """
        raise NotImplementedError("Plugin must implement run()")
    
    def on_finding(self, finding):
        """
        Hook: Called when a new finding is discovered during a scan.
        Override to react to findings in real-time.
        """
        pass
    
    def on_scan_start(self, target, profile):
        """Hook: Called when a scan starts."""
        pass
    
    def on_scan_complete(self, target, findings):
        """Hook: Called when a scan completes."""
        pass


class PluginLoader:
    """Discovers and manages plugins."""
    
    PLUGINS_DIR = os.path.join(os.getcwd(), "plugins")
    
    def __init__(self, log_callback=None):
        self.log = log_callback or (lambda msg: None)
        self.plugins = {}  # name → plugin instance
        self._plugin_classes = {}  # name → plugin class
        self._errors = []
    
    def discover(self):
        """Scan the plugins directory and load all valid plugins."""
        self.plugins.clear()
        self._plugin_classes.clear()
        self._errors.clear()
        
        os.makedirs(self.PLUGINS_DIR, exist_ok=True)
        
        # Create __init__.py if missing
        init_path = os.path.join(self.PLUGINS_DIR, "__init__.py")
        if not os.path.exists(init_path):
            with open(init_path, "w") as f:
                f.write("")
        
        for filename in os.listdir(self.PLUGINS_DIR):
            if filename.endswith(".py") and not filename.startswith("_"):
                self._load_plugin_file(os.path.join(self.PLUGINS_DIR, filename))
        
        count = len(self.plugins)
        if count:
            self.log(f"🔌 {count} plugin(s) loaded: {', '.join(self.plugins.keys())}")
        return self.plugins
    
    def _load_plugin_file(self, filepath):
        """Load a single plugin file."""
        module_name = os.path.splitext(os.path.basename(filepath))[0]
        
        try:
            spec = importlib.util.spec_from_file_location(f"plugins.{module_name}", filepath)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find LockonPlugin subclasses
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, LockonPlugin) and obj is not LockonPlugin:
                    instance = obj(log_callback=self.log)
                    plugin_name = instance.name or name
                    self.plugins[plugin_name] = instance
                    self._plugin_classes[plugin_name] = obj
                    self.log(f"  ▸ {plugin_name} v{instance.version} ({instance.category})")
        except Exception as e:
            error_msg = f"Plugin load error ({module_name}): {e}"
            self._errors.append(error_msg)
            self.log(f"⚠️ {error_msg}")
    
    def get_plugin(self, name):
        """Get a plugin instance by name."""
        return self.plugins.get(name)
    
    def get_all(self):
        """Get all loaded plugins."""
        return list(self.plugins.values())
    
    def get_by_category(self, category):
        """Get plugins filtered by category."""
        return [p for p in self.plugins.values() if p.category == category]
    
    async def run_plugin(self, name, target, session=None, findings=None):
        """Run a specific plugin."""
        plugin = self.plugins.get(name)
        if not plugin:
            return None
        
        self.log(f"🔌 Running plugin: {plugin.name}")
        try:
            results = await plugin.run(target, session=session, findings=findings)
            if results:
                self.log(f"🔌 {plugin.name} returned {len(results)} results")
            return results
        except Exception as e:
            self.log(f"❌ Plugin error ({plugin.name}): {e}")
            return None
    
    async def run_hooks(self, hook_name, *args, **kwargs):
        """Run a hook across all plugins."""
        for plugin in self.plugins.values():
            try:
                method = getattr(plugin, hook_name, None)
                if method and callable(method):
                    method(*args, **kwargs)
            except Exception:
                pass
    
    def list_plugins(self):
        """Return plugin metadata for UI display."""
        return [
            {
                "name": p.name,
                "version": p.version,
                "author": p.author,
                "description": p.description,
                "category": p.category,
            }
            for p in self.plugins.values()
        ]
    
    def get_errors(self):
        """Return any plugin load errors."""
        return self._errors
