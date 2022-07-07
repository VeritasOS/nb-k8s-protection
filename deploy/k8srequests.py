import logging as log
import sys

from kubernetes import client, config


class K8sRequests:
    def __init__(self, namespace) -> None:
        config.load_kube_config()
        self.v1 = client.CoreV1Api()
        self.namespace = namespace

    def getServicAccountToken(self):
        log.info("Getting service accounts")
        svcAccountSecret = ""
        ret = self.v1.read_namespaced_service_account(
            self.namespace + '-backup-server', self.namespace)
        for secret in ret.secrets:
            if secret.name.startswith(self.namespace + "-backup-server-token"):
                svcAccountSecret = secret
                break
        if svcAccountSecret == "":
            log.error("Failed to get service account secret for backup server")
            sys.exit(1)
        log.info("Reading secret token %s", svcAccountSecret.name)
        ret = self.v1.read_namespaced_secret(
            svcAccountSecret.name, self.namespace)
        return ret.data['ca.crt'], ret.data['token']
