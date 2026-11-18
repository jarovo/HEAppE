from typing import Any
from time import sleep

import hvac
import kubernetes
import base64
import kopf
import requests.exceptions
import urllib3.exceptions


VAULT_BOOTSTRAPPER_ID = "vault-bootstrapper.it4i.cz"
VAULT_BOOTSTRAPPER_ANNOTATION = {f"{VAULT_BOOTSTRAPPER_ID}/desired-state": "initialized"}


class FailedToUnsealVault(kopf.TemporaryError):
    pass


@kopf.on.startup()
def configure(settings: kopf.OperatorSettings, **_: Any) -> None:
    settings.scanning.disabled = True
    pass


@kopf.on.create('', 'v1', 'service', annotations=VAULT_BOOTSTRAPPER_ANNOTATION, labels={"vault-internal": "true"})
@kopf.on.timer('', 'v1', 'service', annotations=VAULT_BOOTSTRAPPER_ANNOTATION, labels={"vault-internal": "true"}, interval=30.)
def bootstrap_vault(spec: kopf.Spec, name: str, namespace: str | None, logger: kopf.Logger, **_: Any) -> None:
    ports = {p['name']: p['port'] for p in spec['ports']}

    hvac_client = hvac.Client(
        url=f"http://{name}:{ports['http']}"
    )

    kub_api = kubernetes.client.CoreV1Api()

    try:
        seal_status = hvac_client.sys.read_seal_status()
    except (requests.exceptions.ConnectionError, urllib3.exceptions.NameResolutionError):
        raise kopf.TemporaryError("Vault doesn't seem to be ready yet.", delay=5)


    logger.info(f"Seal status: {seal_status}")
    if not seal_status['initialized']:
        logger.info("Vault is not initialized, initializing now")
        initialize_vault(name, namespace, hvac_client, kub_api, logger)
        logger.info("Vault has been initialized.")

    if seal_status['initialized'] and seal_status['sealed']:
        unseal_vault(name, namespace, hvac_client, kub_api, logger)
        logger.info("Vault has been unsealed.")


def initialize_vault(name: str, namespace: str, hvac_client: hvac.Client, kub_api: kubernetes.client.CoreV1Api, logger: kopf.Logger):
    init_results = hvac_client.sys.initialize(
            secret_shares=1,
            secret_threshold=1
        )

    root_token: str = init_results['root_token']
    unseal_keys: str = init_results['keys']

    unseal_keys_secrets = [
        kubernetes.client.V1Secret(
            metadata=kubernetes.client.V1ObjectMeta(
                name=f"{name}-unseal-key-{n}",
                labels={VAULT_BOOTSTRAPPER_ID: "unseal-key"}
            ),
            data={"unsealKey": base64.b64encode(unseal_key.encode()).decode()}
        ) for n, unseal_key in enumerate(unseal_keys)
    ]

    root_token_secret = kubernetes.client.V1Secret(
        metadata=kubernetes.client.V1ObjectMeta(
            name=f"{name}-root-token",
            annotations={"vaultUrl": hvac_client.url},
            labels={VAULT_BOOTSTRAPPER_ID: "root-token"}
        ),
        data={
            "rootToken": base64.b64encode(root_token.encode()).decode()
        }
    )
    
    #for unseal_key_secret in unseal_keys_secrets:
    #     kopf.adopt(unseal_key_secret)

    #kopf.adopt(root_token_secret)

    for secret in unseal_keys_secrets + [root_token_secret]:    
        try:
            kub_api.create_namespaced_secret(namespace=namespace, body=secret)
            kopf.info(
                None, reason='SecretCreated', message=f'Created secret {secret.metadata.name}'
            )
        except kubernetes.client.ApiException as e:
            if e.status != 409:  # Ignore error if secret already exists
                raise e    


def unseal_vault(name: str, namespace: str, hvac_client: hvac.Client, kub_api: kubernetes.client.CoreV1Api, logger: kopf.Logger):
    secrets = kub_api.list_namespaced_secret(namespace=namespace,
                                             label_selector=f"{VAULT_BOOTSTRAPPER_ID}=unseal-key").items

    logger.info(f"Found {len(secrets)} secrets")
    for secret in secrets:
        vault_unseal_key = base64.b64decode(secret.data['unsealKey']).decode()
        hvac_client.sys.submit_unseal_key(vault_unseal_key)


    for i in range(10):
        seal_status = hvac_client.sys.read_seal_status()
        if not seal_status["sealed"]:
            return
        logger.info(f"Seal status is still: {seal_status}")
        sleep(1)
    else:
        raise FailedToUnsealVault(delay=5)


@kopf.on.create('', 'v1', 'secret', labels={VAULT_BOOTSTRAPPER_ID: "root-token"})
def config(body: kopf.Body, name:str, namespace: str, logger: kopf.Logger, **_: Any):
    kub_api = kubernetes.client.CoreV1Api()

    logger.info(f"Body {namespace}/{name}: {body}, {_}")
    data = body.get('data', {})
    metadata = body.get('metadata', {})
    encoded_token = data.get('rootToken')
    
    if not encoded_token:
        raise kopf.TemporaryError("Secret has no rootToken field.", delay=5)

    token = base64.b64decode(encoded_token).decode()

    hvac_client = hvac.Client(
        url=metadata.get('annotations', {})["vaultUrl"],
        token=token
    )

    try:
        seal_status = hvac_client.sys.read_seal_status()
    except hvac.exceptions.VaultDown:
        kopf.TemporaryError("Vault is down.", delay=5)

    mounts = hvac_client.sys.list_mounted_secrets_engines()

    if "kv-v2/" not in mounts:
        hvac_client.sys.enable_secrets_engine(
            backend_type="kv",
            path="kv-v2",
            options={"version": "2"},
        )
    if "HEAppE/" not in mounts:
        hvac_client.sys.enable_secrets_engine(
            backend_type="kv",
            path="HEAppE",
            options={"version": "2"},
        )

    auth_methods = hvac_client.sys.list_auth_methods()
    approle_mount = auth_methods.get("approle/")

    if approle_mount is None:
        hvac_client.sys.enable_auth_method(method_type="approle")
    elif approle_mount.get("type") != "approle":
        raise RuntimeError(
            "An auth method other than AppRole is already mounted at approle/"
        )

    hvac_client.sys.create_or_update_policy(
        name='heappe-policy',
        policy="""
            path "HEAppE/*"
            {
                capabilities = ["create", "read", "update", "delete", "list", "sudo"]
            }
        """
    )

    hvac_client.auth.approle.create_or_update_approle(
        role_name="heappe-role",
        secret_id_ttl=0,
        token_policies=["heappe-policy"],
        token_num_uses=0,
        token_ttl="5m",
        token_max_ttl="10m",
        secret_id_num_uses=0,
    )

    resp = hvac_client.auth.approle.read_role_id(
        role_name='heappe-role',
    )
    role_id = resp["data"]["role_id"]

    resp = hvac_client.auth.approle.generate_secret_id(
        role_name='heappe-role'
    )
    secret_id = resp["data"]["secret_id"]

    kub_api.create_namespaced_secret(
        namespace=namespace,
        body=kubernetes.client.V1Secret(
            metadata=kubernetes.client.V1ObjectMeta(name="heappe-vault-agent"),
            data={
                "role_id": base64.b64encode(role_id.encode()).decode(),
                "secret_id": base64.b64encode(secret_id.encode()).decode()
            }
        )
    )
    kopf.info(
        None,
        reason="AppRoleConfigured",
        message=f"Created Secret {namespace}/heappe-vault-agent with AppRole credentials.",
    )