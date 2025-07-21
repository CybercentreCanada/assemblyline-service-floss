[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_floss-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-floss)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-floss)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-floss)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-floss)](./LICENSE)
# Floss Service

This service uses FireEye Labs Obfuscated String Solver (FLOSS) to find obfuscated strings such as stacked strings.

https://github.com/fireeye/flare-floss/ - Licensed under Apache License 2.0 (https://github.com/fireeye/flare-floss/blob/master/LICENSE.txt)

## Service Details
This service does the following:

1. String Extraction:
    * executable/windows files:
        - Static strings modules (unicode and ascii). Matches IOC's only
        - Decoded strings modules
        - Stacked strings modules

**When not in deep scan mode, this service will skip detection modules based on a submitted file's size (to prevent service backlog and timeouts). The defaults are intentionally set at low sizes. Filters can be easily changed in the service configuration, based on the amount of traffic/hardware your AL instance is running.**

### Service Configurations

- max_size: Maximum size of submitted file for this service.
- max_length: String length maximum. Used in basic ASCII and UNICODE modules.
- st_max_size: String list maximum size. List produced by basic ASCII and UNICODE module results, and will determine if patterns.py will only evaluate network IOC patterns.

### Result Output

1. Static Strings (ASCII, UNICODE):
    * Strings matching IOC patterns of interest
2. FF Decoded Strings:
    * All strings
    * Strings matching IOC patterns of interest
3. FF Stacked Strings:
    * All strings, group by likeness (determined by fuzzywuzzy library)
    * Strings matching IOC patterns of interest

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
        --name Floss \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-floss

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Floss

Ce service utilise le logiciel FireEye Labs Obfuscated String Solver (FLOSS) pour trouver les chaînes obscurcies telles que les chaînes empilées.

## Détails du service
Ce service permet d'effectuer les opérations suivantes

1. Extraction de la chaîne de caractères :
    * Fichiers exécutables/windows :
        - Modules de chaînes statiques (unicode et ascii). Correspond uniquement aux IOC
        - Modules de chaînes décodés
        - Modules de chaînes empilées

**Lorsqu'il n'est pas en mode d'analyse approfondie, ce service saute des modules de détection en fonction de la taille du fichier soumis (afin d'éviter les retards de service et les dépassements de délai). Les valeurs par défaut sont intentionnellement fixées à des tailles faibles. Les filtres peuvent être facilement modifiés dans la configuration du service, en fonction de la quantité de trafic/du matériel utilisé par votre instance AL**.

### Configurations de service

- max_size : Taille maximale du fichier soumis pour ce service.
- max_length : Longueur maximale d'une chaîne de caractères. Utilisé dans les modules ASCII et UNICODE de base.
- st_max_size : Taille maximale de la liste de chaînes de caractères. Liste produite par les résultats des modules basic ASCII et UNICODE, et qui déterminera si patterns.py n'évaluera que les motifs IOC du réseau.

### Résultat de sortie

1. Chaînes statiques (ASCII, UNICODE) :
    * Chaînes correspondant aux motifs IOC d'intérêt
2. Chaînes décodées FF :
    * Toutes les chaînes
    * Chaînes correspondant à des motifs IOC intéressants
3. FF Stacked Strings (chaînes empilées) :
    * Toutes les chaînes, regroupées par ressemblance (déterminée par la bibliothèque fuzzywuzzy)
    * Chaînes correspondant à des motifs IOC intéressants

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
        --name Floss \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-floss

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
