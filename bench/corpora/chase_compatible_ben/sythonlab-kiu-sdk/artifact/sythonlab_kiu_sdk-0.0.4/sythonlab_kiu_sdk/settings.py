#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
File: settings.py
Author: Sython Lab (sythonlab@gmail.com)
Created: 2026-06-03
"""

import os
import logging
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

load_dotenv(os.path.join(BASE_DIR, ".env"))

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
