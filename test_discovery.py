import unittest

from sthir_net import beacon_message, parse_beacon, parse_seeds

R = [16, 30, 20]


class BeaconTests(unittest.TestCase):
    def test_good_beacon(self):
        m = beacon_message("http://192.168.1.7:5001", R)
        self.assertEqual(parse_beacon(m, "192.168.1.7", R), "http://192.168.1.7:5001")

    def test_beacon_cannot_point_at_someone_else(self):
        m = beacon_message("http://10.0.0.9:5001", R)
        self.assertIsNone(parse_beacon(m, "192.168.1.7", R))

    def test_other_rules_junk_and_oversize_are_ignored(self):
        self.assertIsNone(parse_beacon(beacon_message("http://1.2.3.4:1", [8, 30, 20]), "1.2.3.4", R))
        for bad in (b"", b"not json", b"[]", b'{"sthir":1}', b'{"sthir":2,"url":"http://1.2.3.4:1","rules":[16,30,20]}',
                    b'{"sthir":1,"url":"ftp://1.2.3.4","rules":[16,30,20]}', b"x" * 600):
            self.assertIsNone(parse_beacon(bad, "1.2.3.4", R))


class SeedTests(unittest.TestCase):
    def test_https_only_by_default(self):
        txt = "# c\nhttps://a.example\nhttp://b.example\n  https://c.example  \nftp://x\nhttps://a.example\n"
        self.assertEqual(parse_seeds(txt), ["https://a.example", "https://c.example"])
        self.assertEqual(parse_seeds(txt, allow_http=True), ["https://a.example", "http://b.example", "https://c.example"])

    def test_capped_and_garbage_safe(self):
        self.assertEqual(len(parse_seeds("\n".join(f"https://h{i}.example" for i in range(50)))), 10)
        self.assertEqual(parse_seeds("\x00\xff garbage\n\n"), [])


if __name__ == "__main__":
    unittest.main()
