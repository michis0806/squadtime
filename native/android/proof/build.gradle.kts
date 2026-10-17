plugins { id("com.android.application") }
android {
    namespace = "dev.squadtime.proof"
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.squadtime.proof"
        minSdk = 31
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    sourceSets.getByName("androidTest").assets.srcDir("../../fixtures")
}
dependencies {
    implementation(project(":pairing"))
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
