package com.stratio.sbom.transformer

import com.stratio.sbom.model.GoSdkArtifactBuilder
import com.stratio.sbom.model.SyftSbom

class AddSdkTransformer {

    SyftSbom model
    
    public AddSdkTransformer(SyftSbom model) {
        this.model = model
    }

    public void transform() {        
        // SBOM is preserved if main artifact was developed in any language but golang
        def mainArtifact = this.model.getMainBinaryArtifact()
        if (mainArtifact != null && mainArtifact.language == "go") {
            // Extract main attributes of the main artifact
            def compilerVersion =
                    mainArtifact["metadata"]["goCompiledVersion"].toString().replaceAll("go", "")
            def locationPath = mainArtifact["locations"][0]["path"]
            def locationLayerID = mainArtifact["locations"][0]["layerID"]

            // Create custom builder artifact and relationships
            def builderArtifact =
                    new GoSdkArtifactBuilder(compilerVersion, locationPath, locationLayerID).build()

            this.model.addCustomArtifact(builderArtifact)

            def mainArtifactId = mainArtifact["id"]
            def sourceRelation = this.model.findRelationshipsByChild(mainArtifactId)
            def locationRelation = this.model.findRelationshipsByParent(mainArtifactId)

            def builderSourceRelation =
                    { it -> [parent: it.parent , child: builderArtifact.id, type: it.type]}.call(sourceRelation)
            def builderLocationRelation =
                    { it -> [parent: builderArtifact.id , child: it.child, type: it.type]}.call(locationRelation)
            this.model.addNewArtifactRelationship(builderSourceRelation)
            this.model.addNewArtifactRelationship(builderLocationRelation)
        }
    }
}