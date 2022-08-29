#!/usr/bin/env python3

import os
from urllib.parse import urlparse


def main() -> None:
    aud: str = os.environ["AUDIENCE"].strip()

    if not aud:
        url: str = os.environ["VAULT_URL"]
        fqdn: str = urlparse(url).netloc.split(":")[0]
        aud = fqdn

    print(f"::set-output name=audience::{aud}")


if __name__ == "__main__":
    main()
