package com.stratio.sbom

import com.stratio.sbom.model.GoSdkArtifactBuilder
import com.stratio.sbom.model.Sbom

class GoTransformer {
    static void main(String[] args) {
        // Run Syft to generate SBOM to be tampered
        def sbom = new Sbom(args[0])

        // SBOM is preserved if main artifact was developed in any language but golang
        def mainArtifact = sbom.getMainBinaryArtifact()
        if (mainArtifact != null && mainArtifact.language == "go") {
            // Extract main attributes of the main artifact
            def compilerVersion = mainArtifact["metadata"]["goCompiledVersion"]
            def locationPath = mainArtifact["locations"][0]["path"]
            def locationLayerID = mainArtifact["locations"][0]["layerID"]

            // Create custom builder artifact and relationships
            def builderArtifact =
                    new GoSdkArtifactBuilder(compilerVersion, locationPath, locationLayerID).build()

            sbom.addCustomArtifact(builderArtifact)

            def mainArtifactId = mainArtifact["id"]
            def sourceRelation = sbom.findRelationshipsByChild(mainArtifactId)
            def locationRelation = sbom.findRelationshipsByParent(mainArtifactId)

            def builderSourceRelation =
                    { it -> [parent: it.parent , child: builderArtifact.id, type: it.type]}.call(sourceRelation)
            def builderLocationRelation =
                    { it -> [parent: builderArtifact.id , child: it.child, type: it.type]}.call(locationRelation)
            sbom.addNewArtifactRelationship(builderSourceRelation)
            sbom.addNewArtifactRelationship(builderLocationRelation)
        }
        println sbom.toString()
    }
}
