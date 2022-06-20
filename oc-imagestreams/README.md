# Imagestreams backup and restore with NetBackup
## Introduction
With this solution, we are going to add a way to backup and restore imagestreams in Redhat Openshift Environment. In general, Imagestreams are used while referring images from internal registries.
While doing any K8s Deployment, we need to provide the image which container is going to refer. Normally images are referred from either external registry like docker hub or internal registry. NetBackup protects the applications metadata and PVCs. The images which are hosted on internal registries will not be protected. With this solution, when admin takes backup of a namespace, we will backup the image which the application pods are referring so that admin does not have to worry about the image getting lost.

## Pre-requirement
- Openshift cluster/s (source and target) with internal registries configured and exposed for access.
- An external registry along with a user configured with push and pull permissions.
- Service account which will have the cluster-admin privilege via clusterrolebinding.
- Users need to deploy NetBackup provided deployment which will facilitate backup and restore of imagestreams.
- Internal registry names should be same across Openshift clusters in case recovering to different cluster.

## Solution
Refer sample yaml provided in `sample-yaml` directory.

**Note** - User needs to change the values as per environment. And embed this in application namespace that imagestream and needs protection.

## Constraints
- User will have to use k8s deployments for application deployment.
- While performing restore, User needs to exclude pods, replica sets and imagestreams in the recovery options.
- User will use same namespace name for restore.
