from nbrequests import NetBackupRequests
from k8srequests import K8sRequests

import json
import logging as log
import os
import subprocess
import urllib3
import yaml
import sys
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


with open(os.path.dirname(os.path.realpath(__file__)) + '/data.json') as json_file:
    data = json.load(json_file)['data']

log.basicConfig(format='%(levelname)s %(asctime)s %(filename)s:%(lineno)d: %(message)s',
                    filename='installkops.log',
                    level=log.INFO)


def main():
    nbrq = NetBackupRequests(
        data['nbprimaryserver'], data['authPayload'], data['namespace'], data['k8sPort'])

    securityToken = nbrq.createSecurityToken(data['k8sCluster'])

    sha256Fingerprint = nbrq.getNbcaCertFingerprint()

    nbcert = nbrq.getPrimaryServerCert()

    helmValues = {}
    values = data['helmChartDirPath']+"/values.yaml"
    with open(values, 'r') as file:
        helmValues = yaml.safe_load(file)

    helmValues['netbackupkops']['containers']['manager']['nbcert'] = nbcert
    helmValues['netbackupkops']['containers']['manager']['datamoverimage'] = data['datamoverimage']
    helmValues['netbackupkops']['containers']['manager']['image'] = data['kopsimage']
    helmValues['netbackupkops']['containers']['manager']['k8sCluster'] = data['k8sCluster']
    helmValues['netbackupkops']['containers']['manager']['nbprimaryserver'] = data['nbprimaryserver']
    helmValues['netbackupkops']['containers']['manager']['sha256Fingerprint'] = sha256Fingerprint
    helmValues['netbackupkops']['containers']['manager']['securityToken'] = securityToken

    with open(values, 'w') as file:
        yaml.safe_dump(helmValues, file)

    proc = subprocess.Popen(["helm", "install", "veritas-netbackupkops", "-n", data['namespace'],
                            data['helmChartDirPath']], stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if not line:
            break

    # Wait 15 seconds for service account creation
    time.sleep(15)
    # Add k8s cluster to Netbackup
    k8sreq = K8sRequests(data['namespace'])
    caCert, k8stoken = k8sreq.getServicAccountToken()
    credId = nbrq.addCreds(data['k8sCluster'], caCert, k8stoken)
    nbrq.addK8sCluster(data['k8sCluster'], credId)
    log.info("Done.")


if __name__ == "__main__":
    answer = input("This script will delete existing credentials for given k8s cluster. It will also invalidate existing host mapping with the k8s cluster. Continue? (y/n):")
    if answer.lower() in ["y", "yes"]:
        main()
    elif answer.lower() in ["n", "no"]:
        print("Not making any changes. Exiting.")
    else:
        print("Incorrect input recieved. Valid inputs y/n or yes/no.")
        sys.exit(1)
    sys.exit(0)
