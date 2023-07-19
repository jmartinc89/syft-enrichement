package com.stratio.sbom.model

import groovy.json.JsonOutput
import groovy.json.JsonSlurper

class SyftSbom {

    Object model

    public SyftSbom(String imageUri) {
        def syftProcess = "syft ${imageUri} -o json".execute()
        def jsonParser = new JsonSlurper()
        this.model = jsonParser.parseText(syftProcess.text)
    }

    public SyftSbom(File sbomFile) {
        def jsonParser = new JsonSlurper()
        this.model = jsonParser.parse(sbomFile)
    }

    def getMainBinaryArtifact() {
        //Binary artifacts have no version, identified as devel
        return this.model["artifacts"].find { it["version"] == "(devel)"}
    }

    def getJavaPackages() {
        return this.model["artifacts"].findAll { it["type"] == "java-archive"}.collect { it["name"] }
    }

    def getPackage(String packageName) {
        return this.model["artifacts"].find { it["name"] == packageName}
    }

    def replacePackageUrl(String packageName, String packageUrl) {
        if (packageUrl != null) {
            this.getPackage(packageName)["purl"] = packageUrl
        }
    }

    def addCustomArtifact(artifact) {
        this.model["artifacts"] << artifact
    }

    def addNewArtifactRelationship(artifactRelationship) {
        this.model.artifactRelationships << artifactRelationship
    }

    def findRelationshipsByParent(String parentId) {
        return this.model.artifactRelationships.find { it["parent"] == parentId}
    }

    def findRelationshipsByChild(String childId) {
        return this.model.artifactRelationships.find { it["child"] == childId}
    }

    String toString() {
        return JsonOutput.prettyPrint(JsonOutput.toJson(this.model))
    }
}
