import unittest
from AcdhArcheAssets.file_formats import get_formats, get_by_mtype, get_by_extension

MTYPE = "image/png"
EXTENSION = "png"


class TestNormalizer(unittest.TestCase):
    def test__001_load_list(self):
        items = get_formats()
        self.assertEqual(type(items), list, "should be type 'list' ")

    def test_002_get_by_mtype(self):
        items = get_by_mtype(MTYPE)
        self.assertEqual(type(items), list, "should be list")
        self.assertTrue(EXTENSION in items[0]["extensions"])

    def test_003_get_by_extension(self):
        items = get_by_extension(EXTENSION)
        self.assertEqual(type(items), list, "should be list")
        self.assertTrue(MTYPE in items[0]["MIME_type"])
