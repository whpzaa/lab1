import argparse
import html
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHROME_CANDIDATES = [
    Path(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
    Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"),
]


def find_browser():
    for candidate in CHROME_CANDIDATES:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("Chrome or Edge was not found")


def build_html(title, files):
    sections = []
    line_count = 0
    for file_path in files:
        text = file_path.read_text(encoding="utf-8").strip()
        line_count += len(text.splitlines())
        try:
            label = file_path.relative_to(ROOT)
        except ValueError:
            label = file_path
        sections.append(
            '<section class="card">'
            f'<div class="file">{html.escape(str(label))}</div>'
            f"<pre>{html.escape(text)}</pre>"
            "</section>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    padding: 34px;
    background: radial-gradient(circle at top left, #172554, #080b14 55%);
    color: #e5e7eb;
    font-family: "Cascadia Code", "Consolas", monospace;
  }}
  h1 {{
    margin: 0 0 8px;
    color: #f8fafc;
    font-family: "Segoe UI", sans-serif;
    font-size: 34px;
  }}
  .subtitle {{
    margin-bottom: 26px;
    color: #94a3b8;
    font-family: "Segoe UI", sans-serif;
    font-size: 16px;
  }}
  .card {{
    margin-bottom: 20px;
    overflow: hidden;
    border: 1px solid #334155;
    border-radius: 12px;
    background: #0f172a;
    box-shadow: 0 18px 45px rgba(0, 0, 0, 0.35);
  }}
  .file {{
    padding: 10px 18px;
    border-bottom: 1px solid #263449;
    background: #111c31;
    color: #7dd3fc;
    font-size: 15px;
  }}
  pre {{
    margin: 0;
    padding: 18px;
    color: #d1fae5;
    font-size: 18px;
    line-height: 1.55;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
  }}
</style>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <div class="subtitle">Captured from local execution of the commands shown below.</div>
  {''.join(sections)}
</body>
</html>
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--title", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()

    output_path = (ROOT / args.out).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    input_paths = [
        (ROOT / file_name).resolve() if not Path(file_name).is_absolute() else Path(file_name)
        for file_name in args.files
    ]
    html_source = build_html(args.title, input_paths)

    render_dir = ROOT / "reports" / "evidence-render"
    render_dir.mkdir(parents=True, exist_ok=True)
    html_path = render_dir / f"{output_path.stem}.html"
    html_path.write_text(html_source, encoding="utf-8")

    total_lines = sum(
        len(path.read_text(encoding="utf-8").splitlines()) for path in input_paths
    )
    height = max(1000, min(5200, 360 + total_lines * 40))
    profile_dir = tempfile.mkdtemp(prefix="evidence-chrome-")
    command = [
        str(find_browser()),
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        f"--user-data-dir={profile_dir}",
        f"--window-size=1500,{height}",
        f"--screenshot={output_path}",
        html_path.as_uri(),
    ]
    subprocess.run(command, check=True, capture_output=True)
    print(output_path)


if __name__ == "__main__":
    main()
