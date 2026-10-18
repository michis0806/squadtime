plugins { id("com.android.application") }
android {
    namespace = "dev.squadtime.prototype"
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.squadtime.prototype"
        minSdk = 31
        targetSdk = 36
        versionCode = 1
        versionName = "0.1-dev"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
dependencies {
    implementation(project(":pairing"))
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.3")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

// Deliberately scoped to an explicitly selected private test host; generated files stay in build/.
val generatedNetworkResources = layout.buildDirectory.dir("generated/prototypeNetworkResources")
val generatePrototypeNetworkSecurity by tasks.registering {
    val relayHost = providers.gradleProperty("prototypeRelayHost").orElse("192.0.2.1")
    inputs.property("relayHost",relayHost)
    outputs.dir(generatedNetworkResources)
    doLast {
        val host = relayHost.get()
        require(host.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")))
        val target = generatedNetworkResources.get().file("xml/prototype_network_security.xml").asFile
        target.parentFile.mkdirs()
        target.writeText("""<network-security-config><base-config cleartextTrafficPermitted="false"/><domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="false">$host</domain></domain-config></network-security-config>""")
    }
}
android.sourceSets.getByName("main").res.srcDir(generatedNetworkResources.get().asFile)
tasks.named("preBuild") { dependsOn(generatePrototypeNetworkSecurity) }
