import questionary

from dforge.config_manager import (
    load_config,
    save_config,
)


def settings_workflow():

    config = load_config()

    lang = questionary.select(
        "Default OCR language",
        choices=[
            "eng",
            "hin",
            "tel",
            "tam",
            "jpn",
        ],
        default=config.get(
            "ocr_language",
            "eng",
        ),
    ).ask()

    dpi = int(
        questionary.text(
            "DPI",
            default=str(
                config.get(
                    "ocr_dpi",
                    300,
                )
            ),
        ).ask()
    )

    workers = int(
        questionary.text(
            "Workers",
            default=str(
                config.get(
                    "ocr_workers",
                    4,
                )
            ),
        ).ask()
    )

    config["ocr_language"] = lang
    config["ocr_dpi"] = dpi
    config["ocr_workers"] = workers

    save_config(config)