"""Download pinned official release tools and verify available SHA256 manifests."""
import hashlib
import platform
import subprocess
import tarfile
from pathlib import Path
root=Path(__file__).resolve().parents[1];cache=root/'.cache';cache.mkdir(exist_ok=True);binary=cache/'bin';binary.mkdir(exist_ok=True)
system='darwin' if platform.system()=='Darwin' else 'linux';arch='arm64' if platform.machine() in ['arm64','aarch64'] else 'amd64'
for name,repo,version in [('syft','anchore/syft','1.55.0'),('grype','anchore/grype','0.121.0')]:
    filename=f'{name}_{version}_{system}_{arch}.tar.gz';checksum=f'{name}_{version}_checksums.txt'
    for asset in [filename,checksum]:
        if not (cache/asset).exists():subprocess.run(['gh','release','download','v'+version,'--repo',repo,'--pattern',asset,'--dir',str(cache)],check=True)
    expected=next(line.split()[0] for line in (cache/checksum).read_text().splitlines() if line.split()[-1].lstrip('*')==filename)
    assert hashlib.sha256((cache/filename).read_bytes()).hexdigest()==expected
    with tarfile.open(cache/filename) as archive:
        file=archive.extractfile(name)
        if file is None:raise ValueError('missing tool')
        (binary/name).write_bytes(file.read());(binary/name).chmod(0o755)
asset=f'cosign-{system}-{arch}'
if not (binary/'cosign').exists():
    subprocess.run(['gh','release','download','v2.4.3','--repo','sigstore/cosign','--pattern',asset,'--dir',str(cache)],check=True)
    (cache/asset).replace(binary/'cosign');(binary/'cosign').chmod(0o755)
print('Pinned official tools ready')
