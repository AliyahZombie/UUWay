#!/usr/bin/python3
"""uuway_update_apply: check a downloaded UUWay release, and install it as root.

One file with two halves, because the second half runs as root from a private copy
(`python3 -I -B`, nothing imported from the tree that dpkg is about to replace):

* verification: plain functions that `uuway update` also calls before it asks for root,
  so a bad download is refused before anyone is prompted;
* the transaction: install, prove the machine is back, roll back if it is not.

The release key is pinned twice: the keyring file the package ships, and the primary-key
fingerprints below.  A signature counts only when gpgv, run with an empty home directory
and that one keyring, reports a valid signature from a pinned primary key.
"""
import collections
import hashlib
from pathlib import Path
import re
import subprocess
import tempfile

# The keyring that the installed package ships.  It is read before dpkg replaces the tree,
# so a package that rotates the key is still verified with the key that is already trusted.
KEYRING = Path('/usr/lib/uuway/config/uuway-release.gpg')
# Primary-key fingerprints of the release signing key (upper-case hex).  While this is
# empty nothing is trusted, so an update can never install anything.
TRUSTED_FINGERPRINTS = ()

PACKAGE = 'uuway'
ARCHITECTURE = 'amd64'
TAG = re.compile(r'v((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))')
SUMS_LINE = re.compile(r'([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._+~-]*)')
BAD_STATUS = ('BADSIG', 'ERRSIG', 'EXPKEYSIG', 'REVKEYSIG', 'EXPSIG', 'NO_PUBKEY')
STRONG_HASHES = ('8', '9', '10')  # OpenPGP ids of SHA-256, SHA-384 and SHA-512

Release = collections.namedtuple('Release', 'version deb sha256')


class VerifyError(Exception):
    """A download cannot be trusted; the message says why."""


def deb_name(version):
    return f'{PACKAGE}_{version}_{ARCHITECTURE}.deb'


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for block in iter(lambda: handle.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def parse_sums(text, name):
    """The SHA-256 that SHA256SUMS lists for `name`.

    Every line has to be exactly `<64 lower-case hex>  <file name>`, and the file we want
    has to be listed once; lines for other files are harmless and ignored.
    """
    found = []
    for line in text.splitlines():
        match = SUMS_LINE.fullmatch(line)
        if not match:
            raise VerifyError('SHA256SUMS 里有无法识别的行，拒绝使用。')
        if match.group(2) == name:
            found.append(match.group(1))
    if len(found) != 1:
        raise VerifyError(f'SHA256SUMS 里没有（或重复列出了）{name} 的校验和，拒绝使用。')
    return found[0]


def verify_signature(sums, signature, keyring, fingerprints, *, run=subprocess.run):
    """Raise VerifyError unless `signature` is a good signature over `sums` by a pinned key.

    gpgv gets an empty home directory and the one keyring, so nothing the user (or an
    attacker) put into their own GnuPG setup counts.  The verdict comes from gpgv's status
    lines: an exit code alone says nothing about *whose* signature it was.
    """
    if not fingerprints:
        raise VerifyError('程序里没有写入可信的发布密钥指纹，拒绝安装。')
    if not Path(keyring).is_file():
        raise VerifyError(f'找不到发布公钥 {keyring}，拒绝安装。')
    with tempfile.TemporaryDirectory(prefix='uuway-gpgv-') as home:
        try:
            result = run(['gpgv', '--status-fd', '1', '--homedir', home,
                          '--keyring', str(keyring), str(signature), str(sums)],
                         capture_output=True, text=True, timeout=60, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise VerifyError('无法运行 gpgv，没法校验签名（需要软件包 gpgv）。')
    valid = []
    for line in result.stdout.splitlines():
        if not line.startswith('[GNUPG:] '):
            continue
        fields = line[len('[GNUPG:] '):].split()
        if fields and fields[0] in BAD_STATUS:
            raise VerifyError(f'签名校验失败（{fields[0]}）。')
        if fields and fields[0] == 'VALIDSIG':
            valid.append(fields)
    if result.returncode != 0 or not valid:
        raise VerifyError('签名校验失败：没有来自发布密钥的有效签名。')
    trusted = {fingerprint.upper() for fingerprint in fingerprints}
    for fields in valid:
        # VALIDSIG <signing key> <date> <ts> <expiry> <ver> <rsvd> <pk-algo> <hash-algo> <class> <primary key>
        primary = (fields[10] if len(fields) > 10 else fields[1]).upper()
        if primary not in trusted:
            raise VerifyError(f'签名来自没有写入程序的密钥（指纹 {primary}），拒绝安装。')
        if len(fields) < 9 or fields[8] not in STRONG_HASHES:
            raise VerifyError('签名使用了过弱的哈希算法，拒绝安装。')


def version_is_newer(new, old, *, run=subprocess.run):
    result = run(['dpkg', '--compare-versions', new, 'gt', old],
                 capture_output=True, text=True, timeout=60, check=False)
    if result.returncode not in (0, 1):
        raise VerifyError(f'无法比较版本 {new} 和 {old}。')
    return result.returncode == 0


def deb_control(deb, *, run=subprocess.run):
    result = run(['dpkg-deb', '-f', str(deb), 'Package', 'Version', 'Architecture'],
                 capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        raise VerifyError('无法读取 deb 的控制信息，它不是有效的软件包。')
    fields = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(': ')
        fields[key] = value.strip()
    return fields


def check_release(stage, tag, installed, keyring, fingerprints, *, run=subprocess.run):
    """Verify a staged download; return a Release or raise VerifyError.

    `stage` holds the deb, SHA256SUMS and SHA256SUMS.asc.  Order matters: the signature
    first (nothing in an unsigned file is believed), then the checksum, then what the deb
    says about itself, then that it really is newer than what is installed.
    """
    stage = Path(stage)
    match = TAG.fullmatch(tag)
    if not match:
        raise VerifyError(f'发布标签（tag）必须形如 vX.Y.Z，收到的是 {tag!r}。')
    version = match.group(1)
    name = deb_name(version)
    sums, signature, deb = stage / 'SHA256SUMS', stage / 'SHA256SUMS.asc', stage / name
    for required in (sums, signature, deb):
        if not required.is_file():
            what = '签名文件' if required == signature else '文件'
            raise VerifyError(f'缺少{what} {required.name}（这个版本可能还没有签名）。')
    verify_signature(sums, signature, keyring, fingerprints, run=run)
    expected = parse_sums(sums.read_text(), name)
    actual = sha256_file(deb)
    if actual != expected:
        raise VerifyError(f'{name} 的 SHA-256 与已签名的 SHA256SUMS 不一致（哈希 {actual}），拒绝安装。')
    control = deb_control(deb, run=run)
    if control.get('Package') != PACKAGE:
        raise VerifyError(f'deb 的软件包名是 {control.get("Package")!r}，不是 {PACKAGE}。')
    if control.get('Architecture') != ARCHITECTURE:
        raise VerifyError(f'deb 的架构是 {control.get("Architecture")!r}，不是 {ARCHITECTURE}。')
    if control.get('Version') != version:
        raise VerifyError(f'deb 的版本是 {control.get("Version")!r}，与标签 {tag} 不符。')
    if not version_is_newer(version, installed, run=run):
        raise VerifyError(f'新版本 {version} 不比已安装的 {installed} 更新，拒绝安装。')
    return Release(version, deb, actual)
