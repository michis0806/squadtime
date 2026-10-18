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
    sourceSets.getByName("test").resources.srcDir("../../fixtures")
}
dependencies {
    implementation(project(":pairing"))
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
    implementation("com.google.zxing:core:3.5.3")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

// Deliberately scoped to an explicitly selected private test host; generated files stay in build/.
val generatedNetworkResources = layout.buildDirectory.dir("generated/prototypeNetworkResources")
val generatePrototypeNetworkSecurity by tasks.registering {
    val configuredHost = providers.gradleProperty("prototypeRelayHost")
    val configuredPort = providers.gradleProperty("prototypeRelayPort")
    inputs.property("relayHost",configuredHost.orElse(""))
    inputs.property("relayPort",configuredPort.orElse(""))
    outputs.dir(generatedNetworkResources)
    doLast {
        val host = configuredHost.orNull
        val port = configuredPort.orNull
        val octets = host?.split('.')?.mapNotNull(String::toIntOrNull)
        val isPrivateIpv4 = octets != null && octets.size == 4 && octets.all { it in 0..255 } && when {
            octets[0] == 10 -> true
            octets[0] == 172 -> octets[1] in 16..31
            octets[0] == 192 -> octets[1] == 168
            else -> false
        }
        require(host == null || (host.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) && isPrivateIpv4 && host == octets?.joinToString("."))) {
            "prototypeRelayHost must be a private RFC1918 IPv4 address"
        }
        val portNumber = port?.toIntOrNull()
        require(port == null || (portNumber != null && portNumber in 1024..65535)) {
            "prototypeRelayPort must be an integer from 1024 through 65535"
        }
        val allowlistHost = host ?: "192.0.2.1"
        val target = generatedNetworkResources.get().file("xml/prototype_network_security.xml").asFile
        target.parentFile.mkdirs()
        target.writeText("""<network-security-config><base-config cleartextTrafficPermitted="false"/><domain-config cleartextTrafficPermitted="true"><domain includeSubdomains="false">$allowlistHost</domain></domain-config></network-security-config>""")
        val strings = generatedNetworkResources.get().file("values/prototype_relay.xml").asFile
        strings.parentFile.mkdirs()
        val defaultRelay = if (host == null) "" else "http://$host:${portNumber ?: 8789}"
        strings.writeText("<resources><string name=\"prototype_default_relay\">$defaultRelay</string></resources>")
    }
}
android.sourceSets.getByName("main").res.srcDir(generatedNetworkResources.get().asFile)
tasks.named("preBuild") { dependsOn(generatePrototypeNetworkSecurity) }
