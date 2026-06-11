import importlib_resources
import json


def get_formats():
    """returns a list dicts providing info about file formats and mime types

    :return: list dicts providing info about file formats and mime types
    :rtype: list

    """
    ref = importlib_resources.files("AcdhArcheAssets").joinpath("formats.json")
    with ref.open("r") as fp:
        data = json.load(fp)
    return data


def get_by_mtype(mtype):
    """returns a list of mapping dicts for the provided mime type
    :param mtype: A mime type
    :type mtype: str

    :return: list of mapping dicts for the provided mime type
    :rtype: list

    """

    formats = get_formats()
    matches = [x for x in formats if mtype in x["MIME_type"]]
    return matches


def get_by_extension(extension):
    """returns a list of mapping dicts for the provided extension
    :param extension: A extension
    :type extension: str

    :return: list of mapping dicts for the provided extension
    :rtype: list

    """

    formats = get_formats()
    matches = [x for x in formats if extension in x["extensions"]]
    return matches
