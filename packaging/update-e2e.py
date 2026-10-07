#!/usr/bin/python3
"""End-to-end check of the root side of `uuway update`, inside a clean container.

    update-e2e.py /path/uuway_X_amd64.deb      (as root, with that package installed)

dpkg, apt-get, dpkg-deb and gpgv are the real ones.  What a container cannot have is
stood in for: the desktop session and the user's systemd services (so "is the machine
back?" is scripted) and the clock (so waiting costs nothing).  It runs the installed copy
of uuway_update_apply.py with a throwaway signing key in place of the release key.

Checked: a newer signed version is installed; a tampered, unsigned, replayed, downgraded
or wrongly signed release is refused before anything changes; an update after which the
machine is not healthy is rolled back to the version before it, with dpkg left clean and
every file back as it was.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile

LIB = Path('/usr/lib/uuway')
KEYRING = LIB / 'config/uuway-release.gpg'
spec = importlib.util.spec_from_file_location('uuway_update_apply', LIB / 'scripts/uuway_update_apply.py')
apply = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apply)

failures = []


def check(name, condition, detail=''):
    print(f'  {"✓" if condition else "✗"} {name}')
    if not condition:
        print('      ' + str(detail).replace('\n', '\n      ')[:1500])
        failures.append(name)


def run(*argv, **kwargs):
    check_exit = kwargs.pop('check', True)
    result = subprocess.run([str(a) for a in argv], capture_output=True, text=True, check=False, **kwargs)
    if check_exit and result.returncode != 0:
        sys.exit(f'command failed ({result.returncode}): {" ".join(str(a) for a in argv)}\n{result.stderr.strip()[-800:]}')
    return result


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


class Runner:
    """Real packaging tools; the user's session and services are pretended."""

    def __init__(self):
        self.unhealthy = set()  # package versions after which the bridge does not come up

    def __call__(self, argv, **kwargs):
        argv = [str(part) for part in argv]
        if argv[0] == 'timeout' and 'runuser' in argv:
            inner = argv[argv.index('env') + 1:]
            while inner and '=' in inner[0] and not inner[0].startswith('/'):
                inner = inner[1:]
            return self.as_user(inner)
        if argv[0] == 'systemctl':
            return subprocess.CompletedProcess(argv, 0, stdout='', stderr='')
        if argv[0] == 'ip':
            return subprocess.CompletedProcess(argv, 0, stdout='default via 10.0.0.1 dev eth0\n', stderr='')
        return apply.run_command(argv, **kwargs)

    def as_user(self, inner):
        def done(code=0, out=''):
            return subprocess.CompletedProcess(inner, code, stdout=out, stderr='')
        version = installed_version()
        if inner[:3] == ['systemctl', '--user', 'show-environment']:
            return done(0, 'XDG_SESSION_TYPE=wayland\nXDG_CURRENT_DESKTOP=ubuntu:GNOME\n')
        if inner[:4] == ['systemctl', '--user', 'is-active', '--quiet']:
            return done(0)
        if inner[:3] == ['systemctl', '--user', 'show']:
            blocks = []
            for name in apply.SERVICES:
                up = name != 'uu-native-bridge' or version not in self.unhealthy
                blocks.append(f'NRestarts=0\nId={name}.service\nActiveState={"active" if up else "failed"}\n'
                              f'SubState={"running" if up else "failed"}\nActiveEnterTimestampMonotonic=500\n')
            return done(0, '\n'.join(blocks))
        return done(0)  # `uuway refresh`, daemon-reload, restarts: they work


def installed_version():
    result = run('dpkg-query', '-W', '-f=${Version}', 'uuway', check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def dpkg_clean():
    result = run('dpkg', '--audit', check=False)
    return result.returncode == 0 and not result.stdout.strip()


def package_listing(deb):
    """Mode, owner, size and name of everything in a deb (no dates: a repack has its own).

    /usr/share/doc is left out: the Docker image of Ubuntu excludes it from every package it
    installs, so those files were never on this machine to be repacked.
    """
    lines = run('dpkg-deb', '-c', deb).stdout.splitlines()
    entries = (line.split() for line in lines)
    return sorted((parts[0], parts[1], parts[2], parts[5], *parts[6:]) for parts in entries
                  if not parts[5].startswith('./usr/share/doc/'))


work = Path(tempfile.mkdtemp(prefix='update-e2e-'))
runtime = Path('/run/user')
uid = pwd.getpwnam('tester').pw_uid
(runtime / str(uid)).mkdir(parents=True, exist_ok=True)
(runtime / str(uid) / 'bus').touch()
runner = Runner()
clock = Clock()
baseline = dict(units={name: dict(active=True, restarts=0, entered=500) for name in apply.SERVICES},
                processes={}, connected=None)


def make_key(name):
    home = work / f'gnupg-{name}'
    home.mkdir(mode=0o700)
    base = ['gpg', '--homedir', home, '--batch', '--pinentry-mode', 'loopback', '--passphrase', '']
    run(*base, '--quick-generate-key', f'{name} <{name}@example.invalid>', 'ed25519', 'sign', 'never')
    listing = run(*base, '--with-colons', '--list-keys').stdout
    fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
    keyring = work / f'{name}.gpg'
    keyring.write_bytes(subprocess.run(['gpg', '--homedir', str(home), '--export'], capture_output=True, check=True).stdout)
    return base, fingerprint, keyring


def make_release(version, base, *, source_deb, deb_version=None, tamper=False, sign=True, sums_for=None):
    """A staged release as the updater downloads it, built by repacking `source_deb`."""
    tree = work / f'tree-{version}-{len(list(work.iterdir()))}'
    run('dpkg-deb', '-R', source_deb, tree)
    control = (tree / 'DEBIAN/control').read_text().splitlines()
    (tree / 'DEBIAN/control').write_text(''.join(
        (f'Version: {deb_version or version}\n' if line.startswith('Version:') else line + '\n') for line in control))
    stage = work / f'stage-{version}-{len(list(work.iterdir()))}'
    stage.mkdir()
    deb = stage / apply.deb_name(version)
    run('dpkg-deb', '--root-owner-group', '-Zgzip', '-z1', '-b', tree, deb)
    shutil.rmtree(tree)
    name = apply.deb_name(sums_for or version)
    (stage / 'SHA256SUMS').write_text(f'{hashlib.sha256(deb.read_bytes()).hexdigest()}  {name}\n')
    if sign:
        run(*base, '--yes', '--armor', '--detach-sign', '-o', stage / 'SHA256SUMS.asc', stage / 'SHA256SUMS')
    if tamper:
        with deb.open('ab') as handle:
            handle.write(b'x')
    return stage


def update(tag, stage):
    job = apply.Job(apply.Layout(), user='tester', uid=uid, home='/home/tester', prefix='/home/tester/prefix', tag=tag,
                    baseline=baseline, run=runner, check_run=subprocess.run, clock=clock.now, sleep=clock.sleep,
                    log=lambda text: print('      | ' + text))
    outcome = apply.run_update(job, stage)
    return outcome, apply.read_json(apply.Layout().result)


def scenarios(original):
    base, fingerprint, test_keyring = make_key('release')
    other_base, _, _ = make_key('intruder')
    apply.TRUSTED_FINGERPRINTS = (fingerprint,)

    def trust_the_test_key():
        # The package that is installed ships the real key; the test signs with its own.
        KEYRING.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(test_keyring, KEYRING)

    start = installed_version()
    print(f'  installed: uuway {start}')
    trust_the_test_key()

    print('\n── refused before anything changes (real gpgv, real dpkg-deb)')
    refusals = (
        ('a deb changed after it was signed', '99.0.0', dict(tamper=True)),
        ('a release without a signature', '99.0.0', dict(sign=False)),
        ('a release signed with some other key', '99.0.0', dict(base=other_base)),
        ('an old signed release replayed under a newer tag', '99.0.0', dict(sums_for='98.0.0')),
        ('a deb whose own version is not the tag', '99.0.0', dict(deb_version='99.0.1')),
        ('a version that is not newer than the installed one', '0.0.1', {}),
    )
    for name, version, options in refusals:
        options = dict(options)
        stage = make_release(version, options.pop('base', base), source_deb=original, **options)
        staged_before = sorted(Path('/var/lib/uuway/update/new').glob('*'))
        outcome, result = update(f'v{version}', stage)
        check(f'{name} is refused', outcome == 'not_started' and installed_version() == start and dpkg_clean(),
              f'{outcome} {result} installed={installed_version()}')
        check(f'  and nothing was staged for apt: {name}',
              sorted(Path('/var/lib/uuway/update/new').glob('*')) == staged_before)

    print('\n── a newer signed version is installed')
    stage = make_release('99.0.0', base, source_deb=original)
    outcome, result = update('v99.0.0', stage)
    check('the update succeeds', outcome == 'success', result)
    check('the new version is installed and dpkg is clean', installed_version() == '99.0.0' and dpkg_clean())
    previous = Path('/var/lib/uuway/update/previous') / apply.deb_name(start)
    check('the version it replaced was saved as a deb', previous.is_file(), list(Path('/var/lib/uuway/update').rglob('*')))
    if previous.is_file():
        check('the saved deb says what the installed package said',
              apply.deb_control(previous) == {'Package': 'uuway', 'Version': start, 'Architecture': 'amd64'})
        check('and holds exactly the files, modes and sizes of the original deb',
              package_listing(previous) == package_listing(original),
              f'{set(map(str, package_listing(previous))) ^ set(map(str, package_listing(original)))}')
    check('no resume unit is left behind', not Path('/etc/systemd/system/uuway-update-resume.service').exists())

    print('\n── an update after which the machine is not healthy is rolled back')
    trust_the_test_key()  # installing 99.0.0 brought the real key back
    runner.unhealthy.add('99.0.1')
    stage = make_release('99.0.1', base, source_deb=original)
    outcome, result = update('v99.0.1', stage)
    check('it is rolled back', outcome == 'rolled_back', result)
    check('the version before the update is installed again', installed_version() == '99.0.0', installed_version())
    check('dpkg is left clean', dpkg_clean(), run('dpkg', '--audit', check=False).stdout)
    changed = [line for line in run('dpkg', '-V', 'uuway', check=False).stdout.splitlines() if 'uuway-release.gpg' not in line]
    check('every installed file is as the package says (md5sums)', not changed, '\n'.join(changed))
    check('the result says so', (result or {}).get('outcome') == 'rolled_back' and (result or {}).get('rolled_back_to') == '99.0.0', result)
    check('no resume unit is left behind', not Path('/etc/systemd/system/uuway-update-resume.service').exists())

    return 1 if failures else 0


def main(original):
    """Run the scenarios, then put the release keyring back as it was.

    The test swaps in its own key.  Until the package ships a release key the file is not the
    package's, so dpkg would leave it (and the directory around it) behind on removal.
    """
    had_keyring = KEYRING.exists()
    saved = KEYRING.read_bytes() if had_keyring else b''
    try:
        return scenarios(original)
    finally:
        if had_keyring:
            KEYRING.write_bytes(saved)
        else:
            KEYRING.unlink(missing_ok=True)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    if os.geteuid() != 0 or len(sys.argv) != 2:
        sys.exit('usage: update-e2e.py /path/uuway_X_amd64.deb   (as root)')
    sys.exit(main(Path(sys.argv[1])))
