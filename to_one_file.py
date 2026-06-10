from pathlib import Path

path = Path(".")
text = ""
for file in path.glob("**/*.h"):
    text += "--- " + str(file) + " ---\n\n"
    text += file.read_text()
for file in path.glob("**/*.c"):
    text += "--- " + str(file) + " ---\n\n"
    text += file.read_text()
for file in [Path("Makefile")]:
    text += "--- " + str(file) + " ---\n\n"
    text += file.read_text()
Path("all.txt").write_text(text)
