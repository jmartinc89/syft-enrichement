package com.stratio.sbom.transformer

import com.stratio.sbom.model.GoSdkArtifactBuilder
import com.stratio.sbom.model.SyftSbom
import com.stratio.sbom.model.TrivySbom

class ReplacePackageUrlTransformer {

    SyftSbom model
    TrivySbom model2
    
    public ReplacePackageUrlTransformer(SyftSbom model, TrivySbom model2) {
        this.model = model
        this.model2 = model2
    }

    public void transform() {        
        for (String pkgName in this.model.getJavaPackages()) {
            def pkgUrl = this.model2.getPackageUrl(pkgName)
            this.model.replacePackageUrl(pkgName, pkgUrl)
        }
    }
}