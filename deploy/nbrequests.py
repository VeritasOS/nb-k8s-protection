
import json
import logging as log
import requests
import sys


class NetBackupRequests:
    def __init__(self, nbprimaryserver, authpayload, namespace, k8sPort) -> None:
        '''
        Initiate payload, header and loginurl
        '''

        self.authpayload = authpayload
        self.namespace = namespace
        self.k8sPort = k8sPort
        self.httpsHost = "https://" + nbprimaryserver + ":1556"
        self.loginurl = "https://" + nbprimaryserver + "/netbackup/login"
        self.nbtoken = self.getToken()

    def getToken(self):
        '''
        Get NB token
        '''
        headers = {
            'Content-Type': 'application/vnd.netbackup+json;version=7.0'
        }
        response = requests.request(
            "POST", self.loginurl, json=self.authpayload, headers=headers, verify=False)
        if response.ok:
            return json.loads(response.text)
        log.error("Error during login. Response: %s", response.text)
        return ""

    def generateAPIKey(self, data):
        '''
        Create auth secret yaml file for adding to k8s
        '''
        apiKeyUrl = self.httpsHost + "/netbackup/security/api-keys"

        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'Content-Type': 'application/vnd.netbackup+json;version=3.0'
        }

        response = requests.request(
            "POST", apiKeyUrl, json=data['apiKeyPayload'], headers=authHeaders, verify=False)
        if response.ok:
            log.info("POST response for creating apikey successful")
        else:
            log.error(
                "Failed to generate api key. Delete old api key and try again. %s. Exit.", response.text)
            sys.exit(1)

        apiKeyData = json.loads(response.text)['data']
        apiKey = apiKeyData['attributes']['apiKey']
        log.debug(apiKey)
        return apiKey

    def getPrimaryServerCert(self):

        log.info("Get primary server certificate")
        caCertUrl = self.httpsHost + "/netbackup/security/cacert"
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'Content-Type': 'application/vnd.netbackup+json;version=4.0'
        }

        response = requests.request(
            "GET", caCertUrl, headers=authHeaders, verify=False)
        if response.ok:
            log.info("Successfully read the primary NB CA certificate")
        else:
            log.error("Response %s. Exit.", response.text)
            sys.exit(1)
        caCert = json.loads(response.text)['cacert']
        return caCert[0]

    def addCreds(self, k8sCluster, caCert, k8stoken):
        '''
        Check if credentials exist for given k8sCluster. Delete if they exist and recreate.
        '''
        self.deleteCreds(k8sCluster)
        addK8sCredsPayload = {
            "data": {
                "type": "credentialRequest",
                "attributes": {
                    "name": k8sCluster,
                    "contents": {
                        "token": k8stoken,
                        "caCert": caCert
                    },
                    "description": "Credential for K8s Cluster: " + k8sCluster,
                    "tag": k8sCluster
                }
            }
        }
        addK8sCredsUrl = self.httpsHost + "/netbackup/config/credentials"
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'Content-Type': 'application/vnd.netbackup+json;version=4.0'
        }
        response = requests.request(
            "POST", addK8sCredsUrl, headers=authHeaders, json=addK8sCredsPayload, verify=False)
        if response.ok:
            log.info("POST response for creating credentials successful")
        else:
            log.error("Response %s. Exit.", response.text)
            sys.exit(1)

        credsResult = json.loads(response.text)
        log.info("Add k8s cluster to NetBackup")
        credId = ""
        if credsResult['data']['id'] != "":
            credId = credsResult['data']['id']
        else:
            log.error("Failed to add credentials. Exit.")
            sys.exit(1)
        log.debug("credId: %s", credId)
        return credId

    def deleteCreds(self, credName):
        '''
        Find credential by name and delete the credential
        '''
        k8sCredsUrl = self.httpsHost + "/netbackup/config/credentials"
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'Content-Type': 'application/vnd.netbackup+json;version=4.0'
        }
        response = requests.request(
            "GET", k8sCredsUrl, headers=authHeaders, verify=False)
        if response.ok:
            log.info("GET response for credentials successful")
        else:
            log.error("Response %s. Exit.", response.text)
            sys.exit(1)
        credslist = json.loads(response.text)
        deleteCredId = ""
        for cred in credslist['data']:
            if cred['attributes']['name'] == credName:
                log.info("Credential name exists: %s", cred['attributes']['name'])
                deleteCredId = cred['id']
        if deleteCredId == "":
            log.info("No existing credential found with name %s", credName)
            return

        deleteCredUrl = k8sCredsUrl + "/" + deleteCredId
        response = requests.request(
            "DELETE", deleteCredUrl, headers=authHeaders, verify=False)
        if response.ok:
            log.info("Response for delete credentials successful")
        else:
            log.error("Response %s. Exit.", response.text)
            sys.exit(1)
        return

    def addK8sCluster(self, k8sCluster, credId):

        log.info("Add k8s cluster to NetBackup %s", k8sCluster)
        addK8sClusterPayload = {
            "data": {
                "type": "query",
                "attributes": {
                    "queryName": "add-or-update-cluster",
                    "workloads": [
                        "kubernetes"
                    ],
                    "parameters": {
                        "clusterInfo": {
                            "hostName": k8sCluster,
                            "port": self.k8sPort,
                            "credentialId": credId,
                            "validate": False,
                            "namespace": self.namespace
                        }
                    }
                }
            }
        }
        addK8sClusterUrl = self.httpsHost + "/netbackup/asset-service/queries"
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'Content-Type': 'application/vnd.netbackup+json;version=4.0'
        }

        response = requests.request(
            "POST", addK8sClusterUrl, headers=authHeaders, json=addK8sClusterPayload, verify=False)
        if response.ok:
            log.info("POST response for add k8s cluster successful")
        else:
            log.error("Response %s. Exit.", response.text)
            sys.exit(1)

        addResponse = json.loads(response.text)
        # Check status of add query
        queryId = addResponse['data']['id']
        getk8sClusterAddStatusUrl = self.httpsHost + \
            "/netbackup/asset-service/queries/"+queryId
        response = requests.request(
            "GET", getk8sClusterAddStatusUrl, headers=authHeaders, verify=False)
        if response.ok:
            log.info("Successfully read the query status for adding cluster")
        else:
            log.error("Response %s. Exit.", response.text)
            sys.exit(1)
        getResponse = json.loads(response.text)
        log.debug(getResponse)
        return

    def getNbcaCertFingerprint(self):
        log.info("Get nb cacert sha256fingerprint")
        getCaCertUrl = self.httpsHost + "/netbackup/security/cacert"
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'accept': 'application/vnd.netbackup+json;version=7.0'
        }
        response = requests.request(
            "GET", getCaCertUrl, headers=authHeaders, verify=False)
        if response.ok:
            log.info("Successfully read nbca certificate")
        else:
            log.error("Response %s. Exit.", response.text)
            sys.exit(1)

        caCertResponse = json.loads(response.text)
        sha256Fingerprint = caCertResponse['nbcaCertificateData'][0]['caCertDetails']['sha-256Fingerprint']
        return sha256Fingerprint

    def getHostMappingId(self, k8sCluster):
        hostMappingUrl = self.httpsHost + "/netbackup/config/hosts/hostmappings"
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'accept': 'application/vnd.netbackup+json;version=7.0'
        }
        response = requests.request(
            "GET", hostMappingUrl, headers=authHeaders, verify=False)
        if response.ok:
            log.info("Successfully read hostmappings")
        else:
            log.error("Failed to read hostmappings. Exit.")
            return ""
        hostlist = json.loads(response.text)["hosts"]
        log.debug("Host list %s", hostlist)
        for host in hostlist:
            log.debug("hostName: %s", host['hostName'])
            if host['hostName'] == k8sCluster:
                log.debug("Host uuid %s", host['uuid'])
                return host['uuid']
        log.error("Failed to find host mapping for k8s cluster: %s", k8sCluster)
        return ""

    def addHostMapping(self, k8sCluster, tokenName, securityTokenUrl):
        '''
        Check for existing host mapping. If not present create one by
        adding and deleting a temp nb security token
        '''
        log.info("Add host mapping for k8s cluster")
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'accept': 'application/vnd.netbackup+json;version=7.0'
        }
        tmpTokenName = "temp-" + tokenName
        securityTokenPayload = {
            "allowedCount": 1,
            "reason": "Add temporary token",
            "tokenName": tmpTokenName,
            "validFor": 86313600
        }
        response = requests.request(
            "POST", securityTokenUrl, json=securityTokenPayload, headers=authHeaders, verify=False)
        if response.ok:
            log.info("Successfully created security token %s", tmpTokenName)
        else:
            log.error("Response: %s Status code: %d. Exit.", response.text, response.status_code)
            # sys.exit(1)

        deleteTokenUrl = securityTokenUrl + "/" + tmpTokenName + "/delete"
        deletePayload = {"reason": ""}
        response = requests.request(
            "POST", deleteTokenUrl, json=deletePayload, headers=authHeaders, verify=False)
        if response.ok:
            log.debug("Deleted temporary token. Hostmapping should be created for k8s cluster %s", k8sCluster)
        else:
            log.error("Error while deleting temporary token. Failed to add hostmapping. Exit.")
            sys.exit(1)
        return

    def createSecurityToken(self, k8sCluster):
        '''
        When a fresh security token is created, NB adds hostmapping for respective k8s cluster.
        If kops is uninstalled and user tries to add the security token again, NB does not allow it because
        of existing hostmapping created by earlier token.
        In such a case generating re-issue token is recommended. Creating a re-issue token requires
        hostmapping present for k8s cluster.

        This function checks for existing host mapping, creates one if not present. Then it uses
        the hostmapping to create the security token.
        '''
        log.info("Create nb security token")
        securityTokenUrl = self.httpsHost + "/netbackup/security/securitytokens"
        authHeaders = {
            'Authorization': self.nbtoken['token'],
            'accept': 'application/vnd.netbackup+json;version=7.0'
        }
        tokenName = "nbsecurity-token-" + self.namespace
        hostId = ""
        # Delete existing security token
        deleteTokenUrl = securityTokenUrl + "/" + tokenName + "/delete"
        deletePayload = {"reason": ""}
        response = requests.request(
            "POST", deleteTokenUrl, json=deletePayload, headers=authHeaders, verify=False)
        if response.ok or response.status_code == 409:
            log.debug("Successfully deleted existing token")
        else:
            log.info("%s", response.text)
            self.addHostMapping(k8sCluster, tokenName, securityTokenUrl)

        hostId = self.getHostMappingId(k8sCluster)
        if hostId == "":
            log.error("Failed to create/get host mapping. Exit.")
            # sys.exit(1)

        securityTokenPayload = {
            "allowedCount": 1,
            "hostId": hostId,
            "reason": "Add k8s cluster to NetBackup",
            "tokenName": tokenName,
            "validFor": 86313600
        }
        response = requests.request(
            "POST", securityTokenUrl, json=securityTokenPayload, headers=authHeaders, verify=False)
        if response.ok:
            log.info("Successfully created nb security token %s", tokenName)
        else:
            log.error("Response: %s Status code: %d. Exit.", response.text, response.status_code)
            sys.exit(1)
        securityTokenResponse = json.loads(response.text)
        log.debug(securityTokenResponse['tokenValue'])
        return securityTokenResponse['tokenValue']
