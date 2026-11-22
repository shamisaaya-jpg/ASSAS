"""Turn the owl image into static/owl.png and static/favicon.png (transparent background)."""
import sys
from pathlib import Path

from PIL import Image, ImageDraw


def find_image():
    if len(sys.argv) > 1:
        return Path(sys.argv[1]).expanduser()
    home = Path.home()
    for folder in ["Downloads", "Desktop", "Documents", "Pictures"]:
        for pattern in ["*Logotipo*", "*Coruja*", "*owl*", "*Owl*"]:
            for path in (home / folder).glob(pattern):
                if path.suffix.lower() in {".jpg", ".jpeg", ".png", ".webp"}:
                    return path
    return None


src = find_image()
if not src or not src.exists():
    print("Image not found. Run: python make_logo.py /path/to/your/owl.jpg")
    sys.exit(1)
print("Using:", src)

im = Image.open(src).convert("RGBA")
w, h = im.size

# Remove the white background starting from the borders (keeps the white face feathers)
marker = im.convert("RGB")
for seed in [(0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1),
             (w // 2, 0), (w // 2, h - 1), (0, h // 2), (w - 1, h // 2)]:
    ImageDraw.floodfill(marker, seed, (255, 0, 255), thresh=40)

px, mk = im.load(), marker.load()
for y in range(h):
    for x in range(w):
        if mk[x, y] == (255, 0, 255):
            px[x, y] = (0, 0, 0, 0)

im = im.crop(im.getbbox())
side = max(im.size)
canvas = Image.new("RGBA", (side, side), (0, 0, 0, 0))
canvas.paste(im, ((side - im.size[0]) // 2, (side - im.size[1]) // 2))

Path("static").mkdir(exist_ok=True)
canvas.resize((256, 256), Image.LANCZOS).save("static/owl.png")
canvas.resize((64, 64), Image.LANCZOS).save("static/favicon.png")
print("Created static/owl.png and static/favicon.png")
