import importlib.metadata
import sys

packages = [
    "flet", 
    "requests", 
    "aiohttp", 
    "beautifulsoup4", 
    "playwright", 
    "PyJWT", 
    "dnspython", 
    "colorama", 
    "Pillow", 
    "packaging"
]

results = []
for p in packages:
    try:
        v = importlib.metadata.version(p)
        results.append(f"{p}=={v}")
    except importlib.metadata.PackageNotFoundError:
        # Try lowercase
        try:
            v = importlib.metadata.version(p.lower())
            results.append(f"{p}=={v}")
        except importlib.metadata.PackageNotFoundError:
            results.append(f"# {p} (Not Found in environment)")

with open("current_versions.txt", "w") as f:
    f.write("\n".join(results))

print("Done writing versions.")
