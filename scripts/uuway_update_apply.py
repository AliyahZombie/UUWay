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
import argparse
import collections
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time

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
BAD_STATUS = ('BADSIG', 'EXPKEYSIG', 'REVKEYSIG', 'EXPSIG')
MISSING_KEY = '9'  # the reason code in `ERRSIG`: the signing key is not in the keyring
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
    valid, unknown = [], 0
    for line in result.stdout.splitlines():
        if not line.startswith('[GNUPG:] '):
            continue
        fields = line[len('[GNUPG:] '):].split()
        if fields and fields[0] in BAD_STATUS:
            raise VerifyError(f'签名校验失败（{fields[0]}）。')
        if fields and fields[0] == 'ERRSIG':
            # ERRSIG <keyid> <pk-algo> <hash-algo> <class> <time> <reason> <fpr>
            if len(fields) < 7 or fields[6] != MISSING_KEY:
                raise VerifyError('签名校验失败（ERRSIG：不是缺少公钥，而是别的原因）。')
            unknown += 1  # a signature by a key this install does not know: see below
        if fields and fields[0] == 'VALIDSIG':
            valid.append(fields)
    # While the release key is being replaced a release carries two signatures, and an install
    # that still has only the old key cannot check the new one.  That is fine: what counts is
    # that one signature is valid and from a pinned key.  gpgv then exits with 2 instead of 0.
    if not valid or result.returncode not in ((0, 2) if unknown else (0,)):
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


# ---------------------------------------------------------------------------------------
# The transaction.  Everything below runs as root, from a private copy of this file.
# ---------------------------------------------------------------------------------------

SERVICES = ('uu-native-display', 'uu-native-text', 'uu-native-bridge')
UU_PROCESSES = ('GameViewerServer.exe', 'GameViewerService.exe')
SESSION_KEYS = ('XDG_SESSION_TYPE', 'XDG_CURRENT_DESKTOP', 'WAYLAND_DISPLAY', 'DISPLAY', 'XAUTHORITY')
SESSION_WAIT = 180   # seconds for the desktop session to be there (autologin takes about a minute)
SOAK = 90            # seconds of unbroken health: a watchdog period (30), a restart delay (10) and margin
DEADLINE = 300       # seconds from the end of `refresh` to a verdict
LONG_DEADLINE = 600  # the same, when the desktop session had to come back in between
POLL = 5
REFRESH_TIMEOUT = 900
APT_TIMEOUT = 1800
SUMS_LIMIT = 1 << 20
DEB_LIMIT = 300 << 20
RESUME_UNIT_NAME = 'uuway-update-resume.service'
RESUME_UNIT = '''[Unit]
Description=Finish an interrupted UUWay update

[Service]
Type=oneshot
TimeoutStartSec=infinity
ExecStart=/usr/bin/python3 -I -B {script} resume

[Install]
WantedBy=multi-user.target
'''


class TransactionError(Exception):
    """A step of the update cannot be done; the message says why."""


class Layout:
    """Where the transaction keeps its files and what it reads; tests point it at a temp dir."""

    def __init__(self, state='/var/lib/uuway/update', *, resume_unit='/etc/systemd/system/' + RESUME_UNIT_NAME,
                 proc='/proc', dpkg_info='/var/lib/dpkg/info', runtime='/run/user', root='/'):
        self.state = Path(state)
        self.work = self.state / 'work'
        self.new = self.state / 'new'
        self.previous = self.state / 'previous'
        self.run_dir = self.state / 'run'
        self.journal = self.state / 'journal.json'
        self.result = self.state / 'last-result.json'
        self.progress = self.state / 'progress.log'
        self.recovery = self.state / 'RECOVERY.txt'
        self.lock = self.state / 'lock'
        self.resume_unit = Path(resume_unit)
        self.proc = Path(proc)
        self.dpkg_info = Path(dpkg_info)
        self.runtime = Path(runtime)
        self.root = Path(root)

    def prepare(self):
        # World-readable: users read the result and the progress.  Only `work` is private.
        for directory, mode in ((self.state, 0o755), (self.new, 0o755), (self.previous, 0o755),
                                (self.run_dir, 0o755), (self.work, 0o700)):
            directory.mkdir(mode=mode, parents=True, exist_ok=True)
            os.chmod(directory, mode)


def write_json(path, data, mode=0o644):
    """Replace `path` with `data` so that a reader sees all of the old file or all of the new."""
    path = Path(path)
    temp = path.with_name(path.name + '.new')
    temp.unlink(missing_ok=True)
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(descriptor, 'w') as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def read_json(path, limit=1 << 20):
    """JSON from a file that may belong to someone else: no symlinks, no huge files, or None."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, 'rb') as handle:
            return json.loads(handle.read(limit + 1)[:limit])
    except (OSError, ValueError):
        return None


class Journal:
    """What has been done so far, on disk, so a reboot in the middle can be picked up again."""

    def __init__(self, path, data):
        self.path = Path(path)
        self.data = data

    @classmethod
    def load(cls, path):
        data = read_json(path)
        return cls(path, data) if isinstance(data, dict) else None

    def update(self, **fields):
        self.data.update(fields, updated=time.time())
        write_json(self.path, self.data, 0o600)

    def get(self, key, default=None):
        return self.data.get(key, default)


def run_command(argv, **kwargs):
    """subprocess.run that reports a missing program or a timeout as a failed command."""
    kwargs.setdefault('capture_output', True)
    kwargs.setdefault('text', True)
    kwargs.setdefault('check', False)
    try:
        return subprocess.run([str(part) for part in argv], **kwargs)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, stdout='', stderr='timed out')
    except OSError as error:
        return subprocess.CompletedProcess(argv, 127, stdout='', stderr=str(error))


class Job:
    """One update (or rollback, or resume) with everything it needs and the means to run it."""

    def __init__(self, layout, *, user, uid, home, prefix, tag='', snapshot='', baseline=None,
                 reboot_if_stuck=False, run=run_command, check_run=subprocess.run,
                 clock=time.monotonic, sleep=time.sleep, log=None):
        self.layout = layout
        self.user, self.uid, self.home, self.prefix = user, uid, str(home), str(prefix)
        self.tag, self.snapshot, self.baseline = tag, str(snapshot or ''), baseline
        self.reboot_if_stuck = reboot_if_stuck
        self.run, self.check_run, self.clock, self.sleep = run, check_run, clock, sleep
        self.log = log or (lambda text: print(text, flush=True))
        self.session_env = {}
        self.journal = None

    @property
    def version(self):
        return self.tag[1:]

    def as_user(self, argv, *, timeout=120, session=True):
        """Run a command as the user, inside their systemd user manager's environment."""
        runtime = f'/run/user/{self.uid}'
        environment = [f'XDG_RUNTIME_DIR={runtime}', f'DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus',
                       f'HOME={self.home}', f'USER={self.user}', f'LOGNAME={self.user}']
        if session:
            environment += [f'{key}={value}' for key, value in sorted(self.session_env.items())]
        return self.run(['timeout', str(timeout), 'runuser', '-u', self.user, '--', 'env', *environment, *argv],
                        timeout=timeout + 30)


def progress_logger(layout, clock=time.time):
    """Print to the journal and append to the world-readable progress file `uuway update` follows."""
    def log(text):
        line = f'{time.strftime("%H:%M:%S", time.localtime(clock()))} {text}'
        print(line, flush=True)
        try:
            descriptor = os.open(layout.progress, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
            with os.fdopen(descriptor, 'a') as handle:
                handle.write(line + '\n')
        except OSError:
            pass
    return log


def installed_version(job):
    result = job.run(['dpkg-query', '-W', '-f=${Version}', PACKAGE])
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


def dpkg_is_clean(job):
    result = job.run(['dpkg', '--audit'])
    return result.returncode == 0 and not result.stdout.strip()


# --------------------------------------------------------------------------- health

def parse_environment(text):
    values = {}
    for line in text.splitlines():
        key, separator, value = line.partition('=')
        if separator and key:
            values[key] = value
    return values


def count_uu_processes(proc, uid):
    """{executable: how many of this user's processes run it}.

    Only the file name of argv[0] counts: wine shows the Windows path there, while a shell
    that merely mentions the name on its command line must not be taken for UU.
    """
    counts = {name: 0 for name in UU_PROCESSES}
    wanted = {name.lower(): name for name in UU_PROCESSES}
    for entry in Path(proc).iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            argv0 = (entry / 'cmdline').read_bytes().split(b'\0')[0].decode(errors='replace')
        except OSError:
            continue
        name = re.split(r'[\\/]', argv0)[-1].lower()
        if name in wanted:
            counts[wanted[name]] += 1
    return counts


def _loopback(address):
    """True for 127.0.0.0/8, ::1 and their IPv4-mapped forms, as /proc/net/tcp prints them."""
    host = address.split(':')[0].upper()
    if len(host) == 8:
        return host.endswith('7F')  # little-endian: the first octet is the last byte
    return host == '00000000000000000000000001000000' or (host.startswith('0000000000000000FFFF0000')
                                                          and host.endswith('7F'))


def uu_connected(proc, uid):
    """True when the UU server holds an established connection to a non-local address.

    None when there is no UU server to ask.  This is the closest thing to "UU is online"
    that can be read from the machine without a viewer connecting.
    """
    proc = Path(proc)
    inodes = set()
    servers = 0
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            argv0 = (entry / 'cmdline').read_bytes().split(b'\0')[0].decode(errors='replace')
            if re.split(r'[\\/]', argv0)[-1].lower() != UU_PROCESSES[0].lower():
                continue
            servers += 1
            for descriptor in (entry / 'fd').iterdir():
                target = os.readlink(descriptor)
                if target.startswith('socket:['):
                    inodes.add(target[len('socket:['):-1])
        except OSError:
            continue
    if not servers:
        return None
    for family in ('tcp', 'tcp6'):
        try:
            lines = (proc / 'net' / family).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9 and fields[3] == '01' and fields[9] in inodes and not _loopback(fields[2]):
                return True
    return False


def parse_unit_blocks(text):
    units = {}
    for block in text.strip().split('\n\n'):
        values = parse_environment(block)
        if values.get('Id'):
            units[values['Id'].removesuffix('.service')] = values
    return units


def snapshot_health(job):
    """What the machine looks like now, as plain data (also the baseline taken before an update)."""
    shown = job.as_user(['systemctl', '--user', 'show', *[name + '.service' for name in SERVICES],
                         '-p', 'Id,ActiveState,SubState,NRestarts,ActiveEnterTimestampMonotonic'],
                        session=False, timeout=30)
    blocks = parse_unit_blocks(shown.stdout) if shown.returncode == 0 else {}
    units = {}
    for name in SERVICES:
        values = blocks.get(name, {})
        units[name] = dict(active=values.get('ActiveState') == 'active' and values.get('SubState') == 'running',
                           restarts=int(values.get('NRestarts') or 0),
                           entered=int(values.get('ActiveEnterTimestampMonotonic') or 0))
    return dict(units=units, processes=count_uu_processes(job.layout.proc, job.uid),
                connected=uu_connected(job.layout.proc, job.uid))


def baseline_problems(baseline):
    """Why a machine that is not healthy now cannot be updated safely (empty list: fine)."""
    problems = [f'{name} 没有在运行' for name in SERVICES if not baseline['units'].get(name, {}).get('active')]
    if not baseline['processes'].get(UU_PROCESSES[0]):
        problems.append(f'{UU_PROCESSES[0]} 没有在运行')
    return problems


def judge(baseline, state, *, network_up):
    """Problems in one snapshot, measured against the baseline taken before the update."""
    problems = [f'{name} 没有在运行' for name in SERVICES if not state['units'].get(name, {}).get('active')]
    for name, count in baseline['processes'].items():
        if count and not state['processes'].get(name):
            problems.append(f'{name} 没有在运行')
    if baseline.get('connected') and not state.get('connected') and network_up:
        problems.append('UU 没有连上服务器')
    return problems


def network_is_up(job):
    result = job.run(['ip', 'route', 'show', 'default'])
    return result.returncode == 0 and bool(result.stdout.strip())


def session_present(job):
    result = job.as_user(['systemctl', '--user', 'is-active', '--quiet', 'graphical-session.target'],
                         session=False, timeout=30)
    return result.returncode == 0


def wait_for_session(job, limit=SESSION_WAIT):
    """The desktop session's environment once its user manager holds it; None if it never does.

    The graphical variables only appear in the manager once the desktop is up, so their
    presence is the signal that it is back; they are also what `uuway refresh` insists on.
    """
    end = job.clock() + limit
    while True:
        if (job.layout.runtime / str(job.uid) / 'bus').exists():
            shown = job.as_user(['systemctl', '--user', 'show-environment'], session=False, timeout=30)
            values = parse_environment(shown.stdout) if shown.returncode == 0 else {}
            if values.get('XDG_SESSION_TYPE') == 'wayland' and 'GNOME' in values.get('XDG_CURRENT_DESKTOP', ''):
                return {key: values[key] for key in SESSION_KEYS if key in values}
        if job.clock() >= end:
            return None
        job.sleep(POLL)


Verdict = collections.namedtuple('Verdict', 'healthy reason notes')


def wait_healthy(job, baseline):
    """Watch until the machine has been healthy for SOAK seconds without a break, or give up.

    A flap resets the clock, so a service in a crash loop never gets there.  Whether UU is
    online is judged only against what the baseline showed, and only while the network is up:
    rolling back cannot fix a cable.
    """
    started = job.clock()
    deadline = started + DEADLINE
    stable_since = None
    reference = None
    had_session = True
    drops = 0
    notes = []
    problems = ['还没有检查']
    while True:
        now = job.clock()
        if not session_present(job):
            if had_session:
                drops += 1
                had_session = False
            stable_since = reference = None
            problems = ['桌面会话不在']
            if drops >= 2:
                return Verdict(False, '桌面会话在观察期内重启了两次', notes)
        else:
            had_session = True
            network = network_is_up(job)
            state = snapshot_health(job)
            problems = judge(baseline, state, network_up=network)
            if baseline.get('connected') and not network and 'network' not in notes:
                notes.append('network')
            seen = {name: (unit['restarts'], unit['entered']) for name, unit in state['units'].items()}
            if problems:
                stable_since = reference = None
            elif reference != seen:
                reference, stable_since = seen, now  # the first good reading, or a restart since
            elif now - stable_since >= SOAK:
                return Verdict(True, '', notes)
        if drops:
            deadline = max(deadline, started + LONG_DEADLINE)
        if now >= deadline:
            return Verdict(False, '、'.join(problems), notes)
        job.sleep(POLL)


# ------------------------------------------------------------------ staging and repacking

def copy_private(source, target, limit):
    """Copy one regular file, refusing symlinks and anything over `limit`, into a root-only place."""
    try:
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise VerifyError(f'读不了 {Path(source).name}：{error.strerror}')
    with os.fdopen(descriptor, 'rb') as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise VerifyError(f'{Path(source).name} 不是普通文件。')
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(out, 'wb') as copy:
            copied = 0
            for block in iter(lambda: handle.read(1 << 20), b''):
                copied += len(block)
                if copied > limit:
                    raise VerifyError(f'{Path(source).name} 过大，拒绝使用。')
                copy.write(block)


def copy_stage(job, stage, work):
    """The three downloaded files, copied where only root can change them before they are checked."""
    for name, limit in (('SHA256SUMS', SUMS_LIMIT), ('SHA256SUMS.asc', SUMS_LIMIT),
                        (deb_name(job.version), DEB_LIMIT)):
        copy_private(Path(stage) / name, Path(work) / name, limit)


def repack_installed(job, version):
    """Rebuild the installed package as previous/uuway_<version>_amd64.deb: (path, sha256).

    That deb is what a rollback installs.  It is made from the files on disk, so it does not
    need the old release to still exist or the network to be up at the worst moment.
    """
    layout = job.layout
    status = job.run(['dpkg-query', '-s', PACKAGE])
    if status.returncode != 0 or not status.stdout.strip():
        raise TransactionError('读不到已安装软件包的信息。')
    control = ''.join(line + '\n' for line in status.stdout.splitlines()
                      if not line.startswith(('Status:', 'Config-Version:')))
    try:
        listing = (layout.dpkg_info / f'{PACKAGE}.list').read_text().splitlines()
    except OSError as error:
        raise TransactionError(f'读不到软件包的文件清单：{error.strerror}')
    tree = Path(tempfile.mkdtemp(prefix='repack-', dir=layout.work))
    try:
        os.chmod(tree, 0o755)
        (tree / 'DEBIAN').mkdir(mode=0o755)
        (tree / 'DEBIAN/control').write_text(control)
        for entry in listing:
            relative = entry.strip().lstrip('/')
            if relative in ('', '.'):
                continue
            source, target = layout.root / relative, tree / relative
            if source.is_symlink():
                target.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(os.readlink(source), target)
            elif source.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            elif source.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        for name in ('md5sums', 'preinst', 'postinst', 'prerm', 'postrm'):
            source = layout.dpkg_info / f'{PACKAGE}.{name}'
            if source.is_file():
                shutil.copy2(source, tree / 'DEBIAN' / name)
                os.chmod(tree / 'DEBIAN' / name, 0o644 if name == 'md5sums' else 0o755)
        for old in layout.previous.iterdir():
            old.unlink()
        deb = layout.previous / deb_name(version)
        built = job.run(['dpkg-deb', '--root-owner-group', '-Zgzip', '-z1', '-b', str(tree), str(deb)], timeout=600)
        if built.returncode != 0:
            raise TransactionError(f'重新打包失败：{built.stderr.strip()[-200:]}')
        os.chmod(deb, 0o644)
        readable = job.run(['dpkg-deb', '--fsys-tarfile', str(deb)], text=False, timeout=600)
        if readable.returncode != 0 or deb_control(deb, run=job.run).get('Version') != version:
            raise TransactionError('重新打包出的旧版本读不回来。')
    finally:
        shutil.rmtree(tree, ignore_errors=True)
    return deb, sha256_file(deb)


def simulation_is_safe(output):
    """True when `apt-get -s` would install uuway and nothing else, and remove nothing."""
    installs = 0
    for line in output.splitlines():
        words = line.split()
        if len(words) < 2:
            continue
        if words[0] in ('Remv', 'Purg'):
            return False
        if words[0] == 'Inst':
            if words[1] != PACKAGE:
                return False
            installs += 1
    return installs == 1


# ---------------------------------------------------------------------- the transaction

def arm_resume(job):
    """Make the machine pick the update up again after a reboot; undone by disarm_resume."""
    script = job.layout.run_dir / 'uuway_update_apply.py'
    unit = job.layout.resume_unit
    unit.write_text(RESUME_UNIT.format(script=script))
    os.chmod(unit, 0o644)
    job.run(['systemctl', 'daemon-reload'])
    job.run(['systemctl', 'enable', RESUME_UNIT_NAME])


def disarm_resume(job):
    job.run(['systemctl', 'disable', RESUME_UNIT_NAME])
    job.layout.resume_unit.unlink(missing_ok=True)
    job.run(['systemctl', 'daemon-reload'])


def write_recovery(job, reason):
    journal = job.journal
    text = f'''UUWay 更新（{journal.get('from_version')} → {journal.get('version')}）没有成功，自动回滚也没有恢复：
{reason}

现在这台机器上装的可能是任何一个版本。请在本机或能登录的地方按顺序执行：

1. sudo dpkg --configure -a
2. sudo apt-get install --allow-downgrades {journal.get('previous_deb')}
3. 用普通用户（不要用 root）恢复更新前的快照：
   cp -a {job.snapshot}/home/. ~/
4. systemctl --user daemon-reload && uuway refresh --yes

日志：journalctl -u uuway-update ；进度记录：{job.layout.progress}
'''
    job.layout.recovery.write_text(text)
    os.chmod(job.layout.recovery, 0o644)


def finish_with(job, outcome, message, **extra):
    """Record how it ended, undo the boot-time resume, and clear the working files."""
    journal = job.journal
    recovery = job.layout.recovery if outcome == 'rollback_failed' else None
    data = dict(schema=1, outcome=outcome, message=message, tag=job.tag, finished=time.time(),
                from_version=journal.get('from_version') if journal else None,
                to_version=job.version, snapshot=job.snapshot,
                previous_deb=journal.get('previous_deb') if journal else None,
                log=str(job.layout.progress), recovery=str(recovery) if recovery else None, **extra)
    write_json(job.layout.result, data)
    job.log(f'结果：{outcome}：{message}')
    if journal:
        journal.update(phase='done')
    disarm_resume(job)
    shutil.rmtree(job.layout.work, ignore_errors=True)
    job.layout.work.mkdir(mode=0o700, exist_ok=True)
    for staged in job.layout.new.glob('*'):  # the package is installed (or not); nothing needs this copy
        staged.unlink()
    return outcome


def give_up(job, reason):
    """The rollback did not bring the machine back.  Say how to recover; reboot only if asked to."""
    write_recovery(job, reason)
    journal = job.journal
    if job.reboot_if_stuck and not journal.get('rebooted'):
        journal.update(phase='rebooted', rebooted=True)
        job.log(f'{reason}；按 --reboot-if-stuck 的要求重启一次。')
        write_json(job.layout.result, dict(schema=1, outcome='rollback_failed', message=reason + '（正在重启）',
                                           tag=job.tag, finished=time.time(), recovery=str(job.layout.recovery),
                                           from_version=journal.get('from_version'), to_version=job.version,
                                           snapshot=job.snapshot, previous_deb=journal.get('previous_deb'),
                                           log=str(job.layout.progress)))
        job.run(['systemctl', 'reboot', '--ignore-inhibitors'])
        return 'rebooting'
    return finish_with(job, 'rollback_failed', reason)


def rollback(job, reason):
    """Put the previous version back, restore the user's files, and check the machine again."""
    journal = job.journal
    journal.update(phase='rolling_back', reason=reason)
    job.log(f'开始回滚：{reason}')
    version = journal.get('from_version')
    previous = Path(journal.get('previous_deb') or '/nonexistent')
    installed = False
    if previous.is_file() and sha256_file(previous) == journal.get('previous_sha256'):
        command = ['apt-get', 'install', '-y', '--no-install-recommends', '--allow-downgrades',
                   '-o', 'DPkg::Lock::Timeout=600', str(previous)]
        result = job.run(command, timeout=APT_TIMEOUT)
        if result.returncode != 0:
            job.log('降级失败，先 dpkg --configure -a 再试一次。')
            job.run(['dpkg', '--configure', '-a'], timeout=900)
            result = job.run(command, timeout=APT_TIMEOUT)
        installed = result.returncode == 0 and installed_version(job) == version
        job.log(f'降级到 {version}：{"成功" if installed else "失败"}')
    else:
        job.log('回滚用的旧版本包不见了或已损坏，只能走退路：恢复快照并重启桥接服务。')
    snapshot = Path(job.snapshot) / 'home' if job.snapshot else None
    if snapshot and snapshot.is_dir():
        restored = job.as_user(['cp', '-a', f'{snapshot}/.', f'{job.home}/'], session=False, timeout=300)
        job.log(f'恢复更新前的快照：{"成功" if restored.returncode == 0 else "失败"}')
    job.as_user(['systemctl', '--user', 'daemon-reload'], session=False, timeout=60)
    environment = wait_for_session(job)
    if environment is None:
        return give_up(job, f'{reason}；回滚后桌面会话也没有回来')
    job.session_env = environment
    if installed:
        job.as_user(['/usr/bin/uuway', 'refresh', '--yes', '--prefix', job.prefix], timeout=REFRESH_TIMEOUT)
    else:
        job.as_user(['systemctl', '--user', 'restart', 'uu-native-bridge.service'], timeout=300)
    verdict = wait_healthy(job, job.baseline)
    if verdict.healthy:
        how = '' if installed else '（只恢复了快照并重启桥接服务，软件包仍是新版本）'
        return finish_with(job, 'rolled_back', f'{reason}；已回滚，机器恢复正常{how}。', rolled_back_to=version)
    return give_up(job, f'{reason}；回滚后机器仍不正常：{verdict.reason}')


def complete_update(job):
    """The new package is installed: refresh as the user, then prove the machine is back."""
    job.journal.update(phase='installed')
    environment = wait_for_session(job)
    if environment is None:
        return rollback(job, '更新后桌面会话没有回来')
    job.session_env = environment
    refresh = job.as_user(['/usr/bin/uuway', 'refresh', '--yes', '--prefix', job.prefix], timeout=REFRESH_TIMEOUT)
    job.log(f'uuway refresh 退出码 {refresh.returncode}')
    if refresh.returncode != 0:
        return rollback(job, 'uuway refresh 失败')
    job.journal.update(phase='refreshed')
    verdict = wait_healthy(job, job.baseline)
    if not verdict.healthy:
        return rollback(job, f'更新后机器不正常：{verdict.reason}')
    note = '（网络不通，没法判断 UU 是否在线）' if 'network' in verdict.notes else ''
    return finish_with(job, 'success', f'已更新到 {job.version}。{note}', notes=verdict.notes)


def run_update(job, stage, *, verify=check_release):
    """Verify, back up, install; then complete_update decides between success and rollback."""
    layout, log = job.layout, job.log
    layout.prepare()
    installed = installed_version(job)
    job.journal = Journal(layout.journal, dict(schema=1, phase='starting', tag=job.tag, version=job.version,
                                               from_version=installed, user=job.user, uid=job.uid, home=job.home,
                                               prefix=job.prefix, snapshot=job.snapshot, baseline=job.baseline,
                                               reboot_if_stuck=job.reboot_if_stuck, started=time.time()))
    job.journal.update(phase='starting')
    log(f'开始更新 {installed} → {job.version}')
    if installed is None:
        return finish_with(job, 'not_started', '没有找到已安装的 uuway 软件包。')
    try:
        work = Path(tempfile.mkdtemp(prefix='stage-', dir=layout.work))
        copy_stage(job, stage, work)
        release = verify(work, job.tag, installed, KEYRING, TRUSTED_FINGERPRINTS, run=job.check_run)
        new = layout.new / release.deb.name
        for old in layout.new.iterdir():
            old.unlink()
        shutil.copyfile(release.deb, new)
        os.chmod(new, 0o644)
        if sha256_file(new) != release.sha256:
            raise VerifyError('复制后的 deb 与校验过的不一致。')
    except (VerifyError, OSError) as error:
        return finish_with(job, 'not_started', str(error))
    log('签名、哈希和版本检查通过。')
    try:
        previous, previous_sha = repack_installed(job, installed)
    except (TransactionError, OSError) as error:
        return finish_with(job, 'not_started', f'没法备好回滚用的旧版本，所以没有开始：{error}')
    log(f'已备好回滚用的 {installed}。')
    simulated = job.run(['apt-get', '-s', 'install', '-y', '--no-install-recommends', str(new)], timeout=600)
    if simulated.returncode != 0 or not simulation_is_safe(simulated.stdout):
        return finish_with(job, 'not_started', '模拟安装显示它会动 uuway 以外的软件包，或装不上，所以没有开始。')
    job.journal.update(phase='prepared', previous_deb=str(previous), previous_sha256=previous_sha,
                       new_deb=str(new), new_sha256=release.sha256)
    arm_resume(job)
    job.journal.update(phase='apt')
    log('开始安装。')
    environment = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_SUSPEND='1')
    result = job.run(['apt-get', 'install', '-y', '--no-install-recommends', '-o', 'DPkg::Lock::Timeout=600', str(new)],
                     env=environment, timeout=APT_TIMEOUT)
    now = installed_version(job)
    if result.returncode != 0:
        if now == installed and dpkg_is_clean(job):
            return finish_with(job, 'not_started', 'apt 安装失败，系统没有改变：' + result.stderr.strip()[-300:])
        return rollback(job, 'apt 安装中途失败')
    if now != release.version:
        return rollback(job, f'安装后版本是 {now}，不是 {release.version}')
    return complete_update(job)


def after_reboot(job):
    """The machine was rebooted once on request: judge it once more, and never reboot again."""
    environment = wait_for_session(job)
    if environment is None:
        return finish_with(job, 'rollback_failed', '重启后桌面会话仍然没有回来。')
    job.session_env = environment
    verdict = wait_healthy(job, job.baseline)
    if verdict.healthy:
        return finish_with(job, 'rolled_back', '重启后机器恢复正常。', rolled_back_to=job.journal.get('from_version'))
    return finish_with(job, 'rollback_failed', f'重启后机器仍不正常：{verdict.reason}')


def resume(job):
    """After a reboot in the middle of an update: repair dpkg, then carry on or roll back."""
    journal = job.journal
    phase = journal.get('phase')
    if phase in (None, 'done'):
        disarm_resume(job)
        return 'nothing'
    job.log(f'开机后继续未完成的更新（阶段：{phase}）')
    job.run(['dpkg', '--configure', '-a'], timeout=900)
    now = installed_version(job)
    if phase in ('starting', 'prepared', 'apt'):
        if now == journal.get('from_version') and dpkg_is_clean(job):
            return finish_with(job, 'not_started', '更新在安装前被中断（断电或重启），系统没有改变。')
        if now == journal.get('version'):
            return complete_update(job)
        return rollback(job, '更新被中断，安装状态不明')
    if phase in ('installed', 'refreshed'):
        return complete_update(job)
    if phase == 'rolling_back':
        return rollback(job, journal.get('reason') or '更新被中断')
    if phase == 'rebooted':
        return after_reboot(job)
    return finish_with(job, 'rollback_failed', f'日志里的阶段无法识别：{phase}')


# ------------------------------------------------------------------------------- entry

def acquire_lock(layout):
    """One transaction at a time; the lock lives as long as this process."""
    descriptor = os.open(layout.lock, os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise TransactionError('另一个更新正在进行。')
    return descriptor


def relaunch_from_copy(layout):
    """Run from a private copy: dpkg is about to replace the tree this file was started from."""
    here = Path(__file__).resolve()
    if here.parent == layout.run_dir.resolve():
        return
    copy = layout.run_dir / here.name
    shutil.copyfile(here, copy)
    os.chmod(copy, 0o755)
    os.execv(sys.executable, [sys.executable, '-I', '-B', str(copy), *sys.argv[1:]])


def job_from_journal(layout, journal, **overrides):
    data = journal.data
    job = Job(layout, user=data['user'], uid=data['uid'], home=data['home'], prefix=data['prefix'],
              tag=data['tag'], snapshot=data.get('snapshot', ''), baseline=data.get('baseline'),
              reboot_if_stuck=overrides.pop('reboot_if_stuck', data.get('reboot_if_stuck', False)),
              log=progress_logger(layout), **overrides)
    job.journal = journal
    return job


def parse_args(argv):
    parser = argparse.ArgumentParser(prog='uuway_update_apply', description=__doc__.split('\n\n')[0])
    modes = parser.add_subparsers(dest='mode', required=True)
    apply_parser = modes.add_parser('apply', help='verify, install and check a downloaded release')
    apply_parser.add_argument('--tag', required=True)
    apply_parser.add_argument('--stage', required=True, type=Path)
    apply_parser.add_argument('--user', required=True)
    apply_parser.add_argument('--uid', required=True, type=int)
    apply_parser.add_argument('--home', required=True)
    apply_parser.add_argument('--prefix', required=True)
    apply_parser.add_argument('--snapshot', default='')
    apply_parser.add_argument('--baseline', required=True, type=Path)
    apply_parser.add_argument('--reboot-if-stuck', action='store_true')
    modes.add_parser('resume', help='finish an update that a reboot interrupted')
    rollback_parser = modes.add_parser('rollback', help='go back to the version before the last update')
    rollback_parser.add_argument('--reboot-if-stuck', action='store_true')
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if os.geteuid() != 0:
        sys.exit('uuway_update_apply 必须以 root 运行（由 uuway update 经 sudo 启动）。')
    layout = Layout()
    layout.prepare()
    relaunch_from_copy(layout)
    try:
        lock = acquire_lock(layout)  # noqa: F841  (held until exit)
    except TransactionError as error:
        sys.exit(str(error))
    log = progress_logger(layout)
    if args.mode == 'apply':
        try:
            account = pwd.getpwnam(args.user)
        except KeyError:
            account = None
        job = Job(layout, user=args.user, uid=args.uid, home=args.home, prefix=args.prefix, tag=args.tag,
                  snapshot=args.snapshot, baseline=read_json(args.baseline), reboot_if_stuck=args.reboot_if_stuck,
                  log=log)
        baseline = job.baseline
        if account is None or account.pw_uid != args.uid or account.pw_dir != args.home:
            outcome = finish_with(job, 'not_started', '用户名、uid 和家目录对不上。')
        elif not isinstance(baseline, dict) or not isinstance(baseline.get('units'), dict):
            outcome = finish_with(job, 'not_started', '更新前的健康基线读不出来。')
        else:
            outcome = run_update(job, args.stage)
    else:
        journal = Journal.load(layout.journal)
        if journal is None:
            log('没有更新记录。')
            return 1
        if args.mode == 'resume':
            outcome = resume(job_from_journal(layout, journal))
        else:
            job = job_from_journal(layout, journal, reboot_if_stuck=args.reboot_if_stuck)
            outcome = rollback(job, '按要求手动回滚')
    return 0 if outcome in ('success', 'rolled_back', 'nothing') else 1


if __name__ == '__main__':
    sys.exit(main())
