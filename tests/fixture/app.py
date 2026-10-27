"""Example project for the action's own CI.

Attacker-controlled input (CLI arguments, an HTTP response body) flows into
dependency call sites and into one standard-library sink, so `vdb harden`
has something to decide.
"""

import subprocess
import sys

import jinja2
import requests
import yaml


def fetch(url: str) -> dict:
    # The URL comes straight from the command line.
    resp = requests.get(url, timeout=10)
    return yaml.load(resp.text, Loader=yaml.Loader)


def render(config: dict) -> str:
    template = jinja2.Template(config.get("template", "{{ name }}"))
    return template.render(name=config.get("name", "world"))


def run(config: dict) -> int:
    cmd = config.get("command", "echo ok")
    return subprocess.call(cmd, shell=True)


if __name__ == "__main__":
    cfg = fetch(sys.argv[1])
    print(render(cfg))
    sys.exit(run(cfg))
