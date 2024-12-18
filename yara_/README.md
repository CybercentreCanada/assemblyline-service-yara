[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_yara-blue?logo=github)](https://github.com/CybercentraCanada/assemblyline-service-yara)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-yara)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-yara)
[![License](https://img.shields.io/github/license/CybercentraCanada/assemblyline-service-yara)](./LICENSE)

# Yara Service

This Assemblyline service runs the YARA application against all file types.

## Service Details

### Execution

Currently AL runs YARA 4.3.0, and therefore supports the following external modules:

- Dotnet
- ELF
- Hash
- Magic
- Math
- PE

### Signature Creation

AL YARA rules follow the CCCS standard. Detailed information on writing YARA rules, as well as the MALWARE standard, can be found at the following locations:

Rule creation:

- https://yara.readthedocs.io/en/v4.3.0/

CCCS Standard:

- https://github.com/CybercentreCanada/CCCS-Yara

### Signature sources

Yara uses signature sources to sync it's signature set at a given interval:

The default configured source is the following:

```yaml
sources:
  - name: yr_git
    pattern: .*_index.yar$
    uri: https://github.com/Yara-Rules/rules.git
```

It will run every 24 hours, fetch all rules found in the git repo at the specified URL and make sure they are in sync in the system.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Yara \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-yara

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Yara

Ce service de la ligne d'assemblage exécute l'application YARA pour tous les types de fichiers.

## Détails du service

### Exécution

Actuellement, AL exécute YARA 4.3.0, et supporte donc les modules externes suivants :

- Dotnet
- ELF
- Hash
- Magic
- Math
- PE

### Création de signatures

Les règles AL YARA suivent la norme CCCS. Des informations détaillées sur l'écriture des règles YARA, ainsi que sur la norme MALWARE, sont disponibles aux endroits suivants :

Création de règles :

- https://yara.readthedocs.io/en/v4.3.0/

Norme CCCS :

- https://github.com/CybercentreCanada/CCCS-Yara

### Sources de signature

Yara utilise des sources de signatures pour synchroniser son jeu de signatures à un intervalle donné :

La source configurée par défaut est la suivante :

```yaml
sources:
  - name: yr_git
    pattern: .*_index.yar$
    uri: https://github.com/Yara-Rules/rules.git
```

Il s'exécutera toutes les 24 heures, récupérera toutes les règles trouvées dans le répertoire git à l'URL spécifiée et s'assurera qu'elles sont synchronisées dans le système.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Yara \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-yara

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
