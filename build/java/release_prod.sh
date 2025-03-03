#!/usr/bin/env bash

set -e

BASE_VERSION=$(mvn -q -DforceStdout help:evaluate -Dexpression=project.version)
ARTIFACT_NAME=$(mvn -q -DforceStdout help:evaluate -Dexpression=project.artifactId)
TAG=`echo java/${ARTIFACT_NAME}/v${BASE_VERSION}`

RESULT=$(git tag -l ${TAG})
if [[ "$RESULT" != ${TAG} ]]; then
    # START dry run (TODO: Remove)
    echo "Releasing (DRY RUN): ${ARTIFACT_NAME} v${BASE_VERSION}"
    echo "Tag: ${TAG}, SHA: ${GITHUB_SHA}"
    echo "Exiting without pushing changes"
    exit 0
    # END dry run

    echo "Releasing ${ARTIFACT_NAME} artifact"
    mvn -DskipTests deploy -Prelease

    # Create tag
    git tag -f ${TAG} ${GITHUB_SHA}
    git push origin --tags
    echo "Created tag ${TAG}"
else
    echo "${TAG} exists for ${ARTIFACT_NAME} v${BASE_VERSION}"
fi
