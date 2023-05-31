package com.stratio.sbom.model

import groovy.json.JsonOutput
import groovy.json.JsonSlurper

class Sbom {

    Object sbomModel

    public Sbom(String imageUri) {
        def syftProcess = "syft ${imageUri} -o json".execute()
        def jsonParser = new JsonSlurper()
        this.sbomModel = jsonParser.parseText(syftProcess.text)
    }

    def getMainBinaryArtifact() {
        //Binary artifacts have no version, identified as devel
        return this.sbomModel["artifacts"].find { it["version"] == "(devel)"}
    }

    def addCustomArtifact(artifact) {
        this.sbomModel["artifacts"] << artifact
    }

    def addNewArtifactRelationship(artifactRelationship) {
        this.sbomModel.artifactRelationships << artifactRelationship
    }

    def findRelationshipsByParent(String parentId) {
        return this.sbomModel.artifactRelationships.find { it["parent"] == parentId}
    }

    def findRelationshipsByChild(String childId) {
        return this.sbomModel.artifactRelationships.find { it["child"] == childId}
    }

    String toString() {
        return JsonOutput.prettyPrint(JsonOutput.toJson(this.sbomModel))
    }
}
