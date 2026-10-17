plugins { id("com.android.library") }
android {
    namespace = "dev.squadtime.pairing"
    compileSdk = 36
    defaultConfig { minSdk = 31 }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}

// The Rust artifact is built separately with its checked-in Cargo lockfile.
val repositoryDirectory = rootProject.layout.projectDirectory.dir("../..")
val generatedJni = layout.buildDirectory.dir("generated/mlsJni")
val buildMlsJni by tasks.registering(Exec::class) {
    val sdkDirectory = androidComponents.sdkComponents.sdkDirectory
    inputs.file(repositoryDirectory.file("native/include/squadtime_mls.h"))
    inputs.file(repositoryDirectory.file(".local/native/android/arm64-v8a/libsquadtime_mls_spike.so"))
    inputs.file("src/main/cpp/mls_jni.c")
    inputs.file(rootProject.file("tools/build-jni.sh"))
    outputs.dir(generatedJni)
    doFirst {
        commandLine("bash", rootProject.file("tools/build-jni.sh"), sdkDirectory.get().asFile,
            repositoryDirectory.asFile, generatedJni.get().asFile)
    }
}
android.sourceSets.getByName("main").jniLibs.srcDirs(
    generatedJni.get().asFile, repositoryDirectory.dir(".local/native/android").asFile
)
tasks.named("preBuild") { dependsOn(buildMlsJni) }
