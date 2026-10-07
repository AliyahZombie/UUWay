"""uuway update, user side: what is asked of GitHub, and how little of its answer is believed."""
import email.message
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
try:
    spec = importlib.util.spec_from_file_location("uuway_update", ROOT / "scripts/uuway_update.py")
    update = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(update)
finally:
    sys.path.pop(0)


class FakeResponse(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(body)
        self.headers = email.message.Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeOpener:
    """Answers each request from a table; a value that is an exception is raised instead."""

    def __init__(self, answers):
        self.answers = answers
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        answer = self.answers[request.full_url]
        if isinstance(answer, BaseException):
            raise answer
        return answer


def http_error(code, headers=None):
    message = email.message.Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return urllib.error.HTTPError("https://api.github.com/x", code, "x", message, io.BytesIO(b""))


class RedirectPolicyTests(unittest.TestCase):
    def follow(self, target):
        request = urllib.request.Request("https://github.com/GaryOAO/UUWay/releases/download/v1.2.1/x")
        return update.RedirectPolicy().redirect_request(request, None, 302, "Found", {}, target)

    def test_github_hosts_over_https_are_followed(self):
        for target in ("https://github.com/GaryOAO/UUWay/x",
                       "https://objects.githubusercontent.com/github-production-release-asset/1",
                       "https://release-assets.githubusercontent.com/a/b?sig=1",
                       "https://api.github.com/repos/GaryOAO/UUWay/releases/assets/1"):
            self.assertIsNotNone(self.follow(target), target)

    def test_everything_else_is_refused(self):
        for target in ("http://github.com/x", "https://example.com/x", "https://github.com.example.com/x",
                       "https://githubusercontent.com/x", "https://evilgithubusercontent.com/x",
                       "https://github.com@example.com/x", "https://github.com:8443/x",
                       "ftp://github.com/x", "file:///etc/passwd", "https:///x", "//github.com/x"):
            with self.assertRaises(update.FetchError, msg=target):
                self.follow(target)


class FetcherTests(unittest.TestCase):
    URL = "https://api.github.com/repos/GaryOAO/UUWay/releases/latest"

    def fetcher(self, answers, **options):
        self.opener = FakeOpener(answers)
        return update.Fetcher(opener=self.opener, **options)

    def test_the_body_and_the_etag_come_back(self):
        fetcher = self.fetcher({self.URL: FakeResponse(b"{}", {"ETag": '"abc"'})})
        body, headers = fetcher.get(self.URL, 1024, {"If-None-Match": '"old"'})
        self.assertEqual((body, headers.get("etag")), (b"{}", '"abc"'))
        request = self.opener.requests[0]
        self.assertEqual(request.get_header("If-none-match"), '"old"')
        self.assertTrue(request.get_header("User-agent").startswith("uuway"))

    def test_only_https_urls_are_requested(self):
        fetcher = self.fetcher({})
        for url in ("http://api.github.com/x", "file:///etc/passwd", "ftp://github.com/x", "/etc/passwd"):
            with self.assertRaises(update.FetchError, msg=url):
                fetcher.get(url, 1024)
        self.assertEqual(self.opener.requests, [])

    def test_a_body_over_the_limit_is_refused_whatever_it_claims(self):
        with self.assertRaisesRegex(update.FetchError, "过大"):
            self.fetcher({self.URL: FakeResponse(b"x" * 2000)}).get(self.URL, 1000)
        with self.assertRaisesRegex(update.FetchError, "过大"):  # announced up front: not even read
            self.fetcher({self.URL: FakeResponse(b"x", {"Content-Length": "5000"})}).get(self.URL, 1000)

    def test_the_total_deadline_ends_a_slow_download(self):
        times = iter([0, 1, 2, 500, 501, 502, 503])
        fetcher = self.fetcher({self.URL: FakeResponse(b"x" * 300000)}, deadline=100, clock=lambda: next(times))
        with self.assertRaisesRegex(update.FetchError, "超时"):
            fetcher.get(self.URL, 1 << 20)

    def test_http_failures_are_explained(self):
        cases = ((http_error(404), update.NotFound, "没有"),
                 (http_error(403, {"X-RateLimit-Remaining": "0"}), update.FetchError, "限流"),
                 (http_error(500), update.FetchError, "500"),
                 (urllib.error.URLError("no route"), update.FetchError, "无法连接"),
                 (TimeoutError(), update.FetchError, "无法连接"))
        for failure, kind, words in cases:
            with self.assertRaisesRegex(kind, words, msg=repr(failure)):
                self.fetcher({self.URL: failure}).get(self.URL, 1024)

    def test_not_modified_is_its_own_answer(self):
        with self.assertRaises(update.NotModified):
            self.fetcher({self.URL: http_error(304)}).get(self.URL, 1024, {"If-None-Match": '"abc"'})

    def test_a_file_is_written_privately_and_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "x.deb"
            self.fetcher({self.URL: FakeResponse(b"deb-bytes")}).save(self.URL, target, 1024)
            self.assertEqual(target.read_bytes(), b"deb-bytes")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["x.deb"])

    def test_a_failed_download_leaves_neither_a_file_nor_a_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "x.deb"
            target.write_bytes(b"older download")
            with self.assertRaises(update.FetchError):
                self.fetcher({self.URL: FakeResponse(b"x" * 5000)}).save(self.URL, target, 1000)
            self.assertEqual(target.read_bytes(), b"older download")
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["x.deb"])

    def test_a_symlink_where_the_download_goes_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            victim = Path(directory) / "victim"
            victim.write_text("keep")
            target = Path(directory) / "x.deb"
            Path(str(target) + ".part").symlink_to(victim)
            self.fetcher({self.URL: FakeResponse(b"deb-bytes")}).save(self.URL, target, 1024)
            self.assertEqual(victim.read_text(), "keep")
            self.assertEqual(target.read_bytes(), b"deb-bytes")


def latest_json(**changes):
    data = {"tag_name": "v1.2.1", "draft": False, "prerelease": False, "published_at": "2026-10-08T01:02:03Z",
            "html_url": "https://evil.example/not-used"}
    data.update(changes)
    return json.dumps(data).encode()


class FakeFetcher:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def get(self, url, limit, headers=None):
        self.calls.append(("get", url, limit, dict(headers or {})))
        answer = self.answers[url]
        if isinstance(answer, BaseException):
            raise answer
        return answer, {"etag": '"new"'}

    def save(self, url, path, limit):
        self.calls.append(("save", url, limit))
        answer = self.answers[url]
        if isinstance(answer, BaseException):
            raise answer
        Path(path).write_bytes(answer)


class LatestReleaseTests(unittest.TestCase):
    def latest(self, body=None, **options):
        fetcher = FakeFetcher({update.API_URL: latest_json() if body is None else body})
        return update.latest_release(fetcher, **options), fetcher

    def test_the_newest_published_release_is_read(self):
        release, fetcher = self.latest()
        self.assertEqual((release.tag, release.version, release.etag), ("v1.2.1", "1.2.1", '"new"'))
        self.assertEqual(release.url, "https://github.com/GaryOAO/UUWay/releases/tag/v1.2.1")  # built, not copied
        self.assertEqual(fetcher.calls[0][2], update.SMALL_LIMIT)

    def test_a_cached_etag_is_sent_and_a_304_means_nothing_new_was_published(self):
        _, fetcher = self.latest(etag='"cached"')
        self.assertEqual(fetcher.calls[0][3], {"If-None-Match": '"cached"'})
        self.assertIsNone(update.latest_release(FakeFetcher({update.API_URL: update.NotModified()}), etag='"cached"'))

    def test_no_release_at_all_is_said_plainly(self):
        with self.assertRaisesRegex(update.FetchError, "还没有"):
            update.latest_release(FakeFetcher({update.API_URL: update.NotFound("x")}))

    def test_anything_odd_in_the_answer_is_refused(self):
        for body in (b"not json", b"[]", b"null", latest_json(tag_name="v1.2"), latest_json(tag_name="1.2.1"),
                     latest_json(tag_name="v1.2.1-rc1"), latest_json(tag_name=None), latest_json(tag_name="v1.2.1/../x"),
                     latest_json(draft=True), latest_json(prerelease=True)):
            with self.assertRaises(update.FetchError, msg=body):
                self.latest(body)


class DownloadReleaseTests(unittest.TestCase):
    BASE = "https://github.com/GaryOAO/UUWay/releases/download/v1.2.1/"

    def answers(self, **changes):
        answers = {self.BASE + "SHA256SUMS": b"sums", self.BASE + "SHA256SUMS.asc": b"sig",
                   self.BASE + "uuway_1.2.1_amd64.deb": b"deb"}
        answers.update(changes)
        return answers

    def test_three_files_are_fetched_from_urls_built_from_the_tag(self):
        with tempfile.TemporaryDirectory() as directory:
            fetcher = FakeFetcher(self.answers())
            stage = Path(directory) / "update/1.2.1"
            result = update.download_release(fetcher, "v1.2.1", stage)
            self.assertEqual(result, stage)
            self.assertEqual(sorted(path.name for path in stage.iterdir()),
                             ["SHA256SUMS", "SHA256SUMS.asc", "uuway_1.2.1_amd64.deb"])
            self.assertEqual(stage.stat().st_mode & 0o777, 0o700)
            urls = [call[1] for call in fetcher.calls]
            self.assertTrue(all(url.startswith(self.BASE) for url in urls), urls)
            limits = {call[1].rsplit("/", 1)[1]: call[2] for call in fetcher.calls}
            self.assertEqual(limits["uuway_1.2.1_amd64.deb"], update.DEB_LIMIT)
            self.assertEqual(limits["SHA256SUMS"], update.SMALL_LIMIT)

    def test_a_release_without_a_signature_is_reported_before_the_deb_is_downloaded(self):
        with tempfile.TemporaryDirectory() as directory:
            fetcher = FakeFetcher(self.answers(**{self.BASE + "SHA256SUMS.asc": update.NotFound("x")}))
            with self.assertRaises(update.Unsigned):
                update.download_release(fetcher, "v1.2.1", Path(directory) / "s")
            self.assertFalse(any(call[1].endswith(".deb") for call in fetcher.calls))

    def test_a_bad_tag_is_refused_before_any_request(self):
        fetcher = FakeFetcher({})
        for tag in ("v1.2", "latest", "v1.2.1/../../x", ""):
            with self.assertRaises(update.FetchError, msg=tag):
                update.download_release(fetcher, tag, Path("/nonexistent/stage"))
        self.assertEqual(fetcher.calls, [])


if __name__ == "__main__":
    unittest.main()
