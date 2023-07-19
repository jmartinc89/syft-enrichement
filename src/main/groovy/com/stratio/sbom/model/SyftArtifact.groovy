package com.stratio.sbom.model

class SyftArtifact {
    String id
    String name
    String version
    String type
    String foundBy
    List<Location> locations
    List<String> licenses
    String language
    List<String> cpes
    String purl

    class Location {
        String path
        String layerID
        Map<String,String> annotations = [:]
    }
}
