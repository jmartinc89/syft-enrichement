package com.stratio.sbom.model

import groovy.json.JsonOutput
import groovy.json.JsonSlurper

class TrivySbom {

    Object model
    Map<String,Map<String,String>> packageUrlEntries

    public TrivySbom(String imageUri) {
        def trivyProcess = "trivy image ${imageUri} -f cyclonedx -q".execute()
        def jsonParser = new JsonSlurper()
        this.model = jsonParser.parseText(trivyProcess.text)
        this.extractPackageUrlEntries()
    }

    public TrivySbom(File sbom) {
        def jsonParser = new JsonSlurper()
        this.model = jsonParser.parse(sbom)
        this.extractPackageUrlEntries()
    }

    private void extractPackageUrlEntries() {
        this.packageUrlEntries = this
            .model["components"]
            .findAll{ component -> component["properties"].any { prop -> prop["name"] == "aquasecurity:trivy:PkgType" && prop["value"] == "jar"}}
            .collectEntries { [(it["name"].split(":")[-1]): it["purl"]]}
    }

    def getPackageUrl(String packageName) {
        //Binary artifacts have no version, identified as devel
        return this.packageUrlEntries.get(packageName)
    }

    String toString() {
        return JsonOutput.prettyPrint(JsonOutput.toJson(this.model))
    }
}
