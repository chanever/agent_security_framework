import unittest
from AcdhArcheAssets.uri_norm_rules import get_rules, get_normalized_uri, get_norm_id

SAMPLES = [
    [
        "http://www.geonames.org/1232324343/linz.html",
        "https://sws.geonames.org/1232324343/",
    ],
    ["http://d-nb.info/gnd/4074255-6/", "https://d-nb.info/gnd/4074255-6"],
    ["https://d-nb.info/gnd/4074255-6", "https://d-nb.info/gnd/4074255-6"],
]


URIS = [
    ("http://sws.geonames.org/1232324343/linz.html", "1232324343"),
    ("https://orcid.org/0000-0001-5748-9036", "0000-0001-5748-9036"),
    (
        "https://viaf.org/viaf/106964661/#Napol%C3%A9on_I,_Emperor_of_the_French,_1769-1821",
        "106964661",
    ),  # noqa: E501
    ("https://www.geonames.org/1232324343", "1232324343"),
    ("https://www.wikidata.org/wiki/Q2", "Q2"),
    ("http://vocab.getty.edu/page/tgn/7003199", "7003199"),
    ("https://d-nb.info/gnd/4074255-6", "4074255-6"),
]


class TestNormalizer(unittest.TestCase):
    def test__001_load_list(self):
        rules = get_rules()
        self.assertEqual(type(rules), list, "should be type 'list' ")

    def test__002_test_patterns(self):
        for x in SAMPLES:
            new_uri = get_normalized_uri(x[0])
            self.assertEqual(x[1], new_uri)

    def test__003_test_id_extraction(self):
        for x in URIS:
            new_uri = get_norm_id(x[0])
            self.assertEqual(x[1], new_uri)
