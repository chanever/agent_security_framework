import importlib_resources
import json
import re


def get_rules():
    """returns a list of regex pattern matches

    :return: a list of regex patterns to normalize Authority IDs
    :rtype: list

    """
    ref = importlib_resources.files("AcdhArcheAssets").joinpath("uriNormRules.json")
    with ref.open("r") as fp:
        data = json.load(fp)
    return data


def get_normalized_uri(uri):
    """takes a normdata uri and returns a normlalized version
    :param uri: A normdata uri
    :param type: str

    :return: The normalized URI
    :rtype: str
    """
    for x in get_rules():
        uri = re.sub(x["match"], x["replace"], uri)
    return uri


def get_norm_id(url):
    """takes a normdata URL, e.g. "https://www.wikidata.org/wiki/Q2" and returns the actual ID "Q2"
    :param url: A normdata URL

    :return: The normdata ID
    :rtype: str
    """
    # ToDo: make the whole code more robust
    uri = get_normalized_uri(url)
    rules = get_rules()
    for x in rules:
        try:
            idd = re.findall(x["match"], uri)[0]
        except IndexError:
            continue
        if isinstance(idd, tuple):
            if len(idd) == 2:
                result = idd[0]
            elif len(idd) == 3:
                result = idd[1]
            else:
                result = "-".join(idd)
        else:
            result = idd
        return str(result)
