#!/usr/bin/env groovy
package com.stratio.sbom

import groovy.cli.picocli.CliBuilder

import com.stratio.sbom.transformer.ReplacePackageUrlTransformer
import com.stratio.sbom.transformer.AddSdkTransformer
import com.stratio.sbom.model.SyftSbom
import com.stratio.sbom.model.TrivySbom

class SCAAnalyzer {
    static void main(String[] args) {
        def cli = new CliBuilder(usage:'sbom-go-injector [options] NAME[:TAG]')
        cli.i(longOpt:'input-syft', type: File, 'Provide Syft JSON SBOM as input')
        cli.j(longOpt:'input-trivy', type: File, 'Provide Trivy JSON SBOM as input')
        cli.o(longOpt:'output', type: File, 'Pipe Syft JSON SBOM to File instead of Stdout')
        cli.t(longOpt:'transform', args: '+', valueSeparator: ',', type: String[], 'List of transformers used')
        //sdk, purl
        cli.h(longOpt:'help', 'Print this help and exit.')
        
        def options = cli.parse(args)
        if (options.h) {
            cli.usage()
            System.exit 0
        }

        def registryUrl = options.arguments()[0]

        SyftSbom inputSyft
        if (options.i) {
            inputSyft = new SyftSbom(options.i)
        } else {
            inputSyft = new SyftSbom(registryUrl)
            new File("${registryUrl.split("/")[-1]}-syft.json").withWriter('utf8') { writer ->
                writer.write(inputSyft.toString())
            }
        }

        for (String transformerId in options.ts) {
            if (transformerId=="sdk") {
                new AddSdkTransformer(inputSyft).transform()
            } else if (transformerId=="purl") {
                TrivySbom inputTrivy
                if (options.j) {
                    inputTrivy = new TrivySbom(options.j)
                } else {
                    inputTrivy = new TrivySbom(registryUrl)
                    new File("${registryUrl.split("/")[-1]}-trivy.json").withWriter('utf8') { writer ->
                        writer.write(inputTrivy.toString())
                    }
                }
                new ReplacePackageUrlTransformer(inputSyft, inputTrivy).transform()
            }
        }

        if (options.o) {
            println options.arguments()
            println options.o
            println options.ts
            
            new File("${registryUrl.split("/")[-1]}-mod.json").withWriter('utf8') { writer ->
                writer.write(inputSyft.toString())
            }
        } else {
            print(inputSyft.toString())
        }
    }
}