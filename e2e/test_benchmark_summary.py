from pathlib import Path
import runpy
import tempfile
import unittest

summarize = runpy.run_path(str(Path(__file__).with_name("benchmark-summary.py")))["summarize"]


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        for daemon, rate in [("go", 100), ("rust", 110), ("direct", 105)]:
            name = "BenchmarkTransferRateBaseline" if daemon == "direct" else "BenchmarkTransferRate"
            for trial in range(1, 7):
                text = "".join(
                    f"{name}/{case}-4 10 123456 ns/op {rate:.2f} MB/s\n"
                    for case in ("scp_upload", "ssh_stream")
                )
                (self.directory / f"{daemon}-{trial}.log").write_text(text, encoding="utf-8")

    def test_paired_rates_and_ratios(self):
        summary, passed = summarize(self.directory)
        self.assertTrue(passed)
        self.assertIn("| 100.00 | 110.00 | 105.00 | 110.0% | 110.0-110.0% | 104.8% | 95.2% |", summary)

    def test_preserves_direct_threshold(self):
        for rate, passed in [(94.5, True), (94.4, False)]:
            for trial in range(1, 7):
                path = self.directory / f"rust-{trial}.log"
                path.write_text("".join(
                    f"BenchmarkTransferRate/{case}-4 10 123456 ns/op {rate} MB/s\n"
                    for case in ("scp_upload", "ssh_stream")
                ), encoding="utf-8")
            self.assertEqual(summarize(self.directory)[1], passed)

    def test_missing_sample_fails(self):
        (self.directory / "rust-6.log").unlink()
        with self.assertRaises(FileNotFoundError):
            summarize(self.directory)

    def test_duplicate_zero_or_mislabeled_results_fail(self):
        path = self.directory / "rust-1.log"
        original = path.read_text(encoding="utf-8")
        for text in [original * 2, original.replace("110.00", "0.00"),
                     original.replace("TransferRate/", "TransferRateBaseline/")]:
            path.write_text(text, encoding="utf-8")
            with self.assertRaises(ValueError):
                summarize(self.directory)


if __name__ == "__main__":
    unittest.main()
