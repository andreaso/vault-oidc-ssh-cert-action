import os
import subprocess
import tempfile
import urllib.parse

import requests


class VoscaError(Exception):
    pass


def _mask_value(secret: str) -> None:
    print(f"::add-mask::{secret}")


def _set_error_message(title: str, message: str) -> None:
    print(f"::error title={title}::{message}")


def _set_warning_message(title: str, message: str) -> None:
    print(f"::warning title={title}::{message}")


def _set_step_output(name: str, value: str) -> None:
    with open(os.environ["GITHUB_OUTPUT"], mode="a", encoding="utf-8") as ghof:
        ghof.write(f"{name}={value}\n")


def _check_inputs() -> None:
    required_inputs = [
        "oidc_backend_path",
        "oidc_role",
        "ssh_backend_path",
        "ssh_role",
        "vault_server",
    ]
    missing_inputs: list[str] = []
    for input in required_inputs:
        if not os.environ.get(input.upper(), "").strip():
            missing_inputs.append(input)

    if not missing_inputs:
        return

    title = "Missing Action input(s)"
    message = f"Missing required input(s): {','.join(missing_inputs)}"
    _set_error_message(title, message)
    raise VoscaError(title)


def _determine_audience(input_audience: str, vault_server: str) -> str:
    if input_audience:
        return input_audience

    vault_fqdn = urllib.parse.urlparse(vault_server).netloc.split(":")[0]
    if vault_fqdn:
        return vault_fqdn

    title = "Default JWT audience error"
    message = "Failed to extract a default JWT audience from the vault_server input."
    _set_error_message(title, message)
    raise VoscaError(title)


def _issue_github_jwt(jwt_aud: str) -> str:
    try:
        req_token = os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]
        req_url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"]
    except KeyError as key_error:
        title = "GitHub Actions workflow/job permission error"
        helper_url = "/".join(
            [
                "https://docs.github.com/en/actions/deployment",
                "security-hardening-your-deployments",
                "about-security-hardening-with-openid-connect#adding-permissions-settings",
            ]
        )
        message = "The `id-token: write` permission appear to be missing."
        message += f" See {helper_url} for more info."
        _set_error_message(title, message)
        raise VoscaError(title) from key_error

    full_url = f"{req_url}&audience={jwt_aud}"
    headers = {"Authorization": f"Bearer {req_token}"}

    try:
        response = requests.get(full_url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as request_error:
        title = "GitHub Actions JWT token issuing error"
        message = f"{type(request_error).__name__}: {str(request_error)}"
        _set_error_message(title, message)
        raise VoscaError(title) from request_error

    jwt_token: str = response.json()["value"]
    return jwt_token


def _issue_vault_token(
    vault_server: str, oidc_backend: str, oidc_role: str, jwt_token: str
) -> str:
    login_url = f"{vault_server}/v1/auth/{oidc_backend}/login"
    payload = {"jwt": jwt_token, "role": oidc_role}

    try:
        response = requests.post(login_url, data=payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as request_error:
        title = "Vault login error"
        message = f"{type(request_error).__name__}: {str(request_error)}"
        _set_error_message(title, message)
        raise VoscaError(title) from request_error

    vault_token: str = response.json()["auth"]["client_token"]
    _mask_value(vault_token)
    return vault_token


def _issue_ssh_cert(
    vault_server: str, vault_token: str, ssh_backend: str, ssh_role: str, pubkey: str
) -> str:
    issue_url = f"{vault_server}/v1/{ssh_backend}/sign/{ssh_role}"
    headers = {"X-Vault-Token": vault_token}
    payload = {"public_key": pubkey}

    try:
        response = requests.post(issue_url, headers=headers, data=payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as request_error:
        title = "Vault SSH certificate signing error"
        message = f"{type(request_error).__name__}: {str(request_error)}"
        _set_error_message(title, message)
        raise VoscaError(title) from request_error

    ssh_cert: str = response.json()["data"]["signed_key"]
    return ssh_cert


def _generate_and_sign(
    vault_server: str, vault_token: str, ssh_backend: str, ssh_role: str
) -> tuple[str, str]:
    key_fname = "id_github"
    cert_fname = f"{key_fname}-cert.pub"

    outdir = tempfile.mkdtemp(prefix="ssh-cert-")
    out_key_path = os.path.join(outdir, key_fname)
    out_cert_path = os.path.join(outdir, cert_fname)

    with tempfile.TemporaryDirectory(prefix="ssh-keygen-") as workdir:
        work_key_path = os.path.join(workdir, key_fname)
        work_pub_path = os.path.join(workdir, f"{key_fname}.pub")
        work_cert_path = os.path.join(workdir, cert_fname)

        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", work_key_path],
            check=True,
        )

        with open(work_pub_path, mode="r", encoding="utf-8") as pubkf:
            pubkey = pubkf.read()

        ssh_cert: str = _issue_ssh_cert(
            vault_server, vault_token, ssh_backend, ssh_role, pubkey
        )
        with open(work_cert_path, mode="w", encoding="utf-8") as certf:
            certf.write(ssh_cert)

        os.rename(work_key_path, out_key_path)
        os.rename(work_cert_path, out_cert_path)

    return out_cert_path, out_key_path


def _revoke_token(vault_server: str, vault_token: str) -> None:
    revoke_url = f"{vault_server}/v1/auth/token/revoke-self"
    headers = {"X-Vault-Token": vault_token}

    try:
        response = requests.post(revoke_url, headers=headers, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as request_error:
        title = "Vault token revoke failure"
        message = f"{type(request_error).__name__}: {str(request_error)}"
        _set_warning_message(title, message)


def run() -> None:
    _check_inputs()

    input_audience = os.environ["JWT_AUDIENCE"].strip()
    oidc_role = os.environ["OIDC_ROLE"].strip()
    oidc_backend = os.environ["OIDC_BACKEND_PATH"].strip("/ ")
    ssh_role = os.environ["SSH_ROLE"].strip()
    ssh_backend = os.environ["SSH_BACKEND_PATH"].strip("/ ")
    vault_server = os.environ["VAULT_SERVER"].strip("/ ")

    jwt_aud: str = _determine_audience(input_audience, vault_server)
    jwt_token: str = _issue_github_jwt(jwt_aud)
    vault_token: str = _issue_vault_token(
        vault_server, oidc_backend, oidc_role, jwt_token
    )

    cert_path: str
    key_path: str
    cert_path, key_path = _generate_and_sign(
        vault_server, vault_token, ssh_backend, ssh_role
    )

    _set_step_output("cert_path", cert_path)
    _set_step_output("key_path", key_path)

    _revoke_token(vault_server, vault_token)
