# w osobnym skrypcie lub python REPL
from pathlib import Path
p = Path("../server/packages/update.zip")
data = bytearray(p.read_bytes())
data[100] ^= 0xFF  # flip bajt na pozycji 100
p.write_bytes(data)