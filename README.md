# Vault OIDC SSH Certificate Action

This action uses [GitHub's OIDC support][1] to authenticate towards a
HashiCorp Vault instance, and to request a (short-lived) SSH client
certificate from it.


## Example Usage

```yaml
jobs:
  deploy:
    permissions:
      contents: read
      id-token: write
    # ...
    steps:
      # ...
      - name: Generate SSH client certificate
        if: github.ref == 'refs/heads/main'
        id: ssh_cert
        uses: andreaso/vault-oidc-ssh-cert-action@v0.10
        with:
          vault_server: https://vault.example.com:8200
          oidc_backend_path: github-oidc
          oidc_role: example-user
          ssh_backend_path: ssh-client-ca
          ssh_role: github-actions-example

      - name: Deploy site
        if: github.ref == 'refs/heads/main'
        run: >
          rsync -e "ssh -i '$SSH_KEY_PATH'"
          --verbose --recursive --delete-after --perms --chmod=D755,F644
          build/ deployer@site.example.net:/var/www/site/
        env:
          SSH_KEY_PATH: ${{ steps.ssh_cert.outputs.key_path }}
```

Do note that all client certification configuration is expected to
happen on the Vault end, given that that is where all the limitations
can be enforced.


## Corresponding Configuration

### HashiCorp Vault

```terraform
resource "vault_jwt_auth_backend" "github" {
  path               = "github-oidc"
  oidc_discovery_url = "https://token.actions.githubusercontent.com"
  bound_issuer       = "https://token.actions.githubusercontent.com"
}

resource "vault_mount" "ssh_ca" {
  path        = "ssh-client-ca"
  type        = "ssh"
}

resource "vault_ssh_secret_backend_ca" "ssh_ca" {
  backend = vault_mount.ssh_ca.path
}
```

```terraform
resource "vault_ssh_secret_backend_role" "example" {
  name                    = "github-actions-example"
  backend                 = vault_mount.ssh_ca.path
  max_ttl                 = "900"
  key_type                = "ca"
  allow_user_certificates = true
  allow_host_certificates = false
  allowed_users           = "github-deploy@example.com"
  default_user            = "github-deploy@example.com"
  default_extensions      = {}

  allowed_user_key_config {
    type    = "ed25519"
    lengths = [0]
  }
}

data "vault_policy_document" "example" {
  rule {
    path         = "${vault_mount.ssh_ca.path}/sign/${vault_ssh_secret_backend_role.example.name}"
    capabilities = ["update"]
  }
}

resource "vault_policy" "example" {
  name   = "example-policy"
  policy = data.vault_policy_document.example.hcl
}

resource "vault_jwt_auth_backend_role" "example" {
  backend         = vault_jwt_auth_backend.github.path
  role_type       = "jwt"
  role_name       = "example-user"
  token_max_ttl   = "300"
  token_policies  = [vault_policy.example.name]
  user_claim      = "actor"
  bound_audiences = ["vault.example.com"]
  bound_claims    = {
    repository = "OWNER/REPO-NAME",
    ref        = "refs/heads/main",
  }
}
```

```terraform
output "ssh_ca" {
  value = vault_ssh_secret_backend_ca.ssh_ca.public_key
}
```

### OpenSSH

```ssh-config
# /etc/ssh/sshd_config
# ...
TrustedUserCAKeys /etc/ssh/sshd_user_ca.pub
AuthorizedPrincipalsFile /etc/ssh/user_principals/%u
```

```text
# /etc/ssh/sshd_user_ca.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...
```

```text
# /etc/ssh/user_principals/deployer
github-deploy@example.com
```


[1]: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
