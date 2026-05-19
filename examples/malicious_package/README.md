# Malicious Package Demo

This example is intentionally suspicious. Installing it runs `setup.py`, which
tries to read the sandbox dummy SSH key and then attempts a blocked network POST.
It is designed to verify that the real environment never runs the install.
