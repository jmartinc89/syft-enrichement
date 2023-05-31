package com.stratio.sbom.model

class GoSdkArtifactBuilder {
    String id
    String name
    String version
    String type
    String foundBy
    List<Artifact.Location> locations = []
    List<String> cpes = []
    String purl

    public GoSdkArtifactBuilder(String version, String evidencePath, String evidenceLayer) {
        this.id = Long.toHexString(new Random().nextLong())
        this.name = "go"
        this.version = version
        this.type = "stdlib"
        this.foundBy = "injected-ci-flow"
        def location = new Artifact.Location()
        location.layerID = evidenceLayer
        location.path = evidencePath
        location.annotations = [evidence: 'primary']
        this.locations << location
        this.cpes << "cpe:2.3:a:golang:${this.name}:${this.version}:*:*:*:*:*:*:*"
        this.cpes << "cpe:2.3:a:go:${this.name}:${this.version}:*:*:*:*:*:*:*"
        this.purl = "pkg:generic/${this.name}@${this.version}"
    }

    public Artifact build(){
        def artifact = new Artifact()
        artifact.id = this.id
        artifact.name = this.name
        artifact.version = this.version
        artifact.type = this.type
        artifact.foundBy = this.foundBy
        artifact.locations = this.locations
        artifact.licenses = []
        artifact.cpes = this.cpes
        artifact.purl = this.purl
        return artifact
    }
}
