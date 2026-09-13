from pathlib import Path


def demo_page():
    return (Path(__file__).resolve().parents[3] / "fixtures" / "demo" / "page.html").read_text()
