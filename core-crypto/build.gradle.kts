plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.notificationmirroring.crypto"
    compileSdk = 35
    defaultConfig {
        minSdk = 29
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    sourceSets.getByName("test").resources.srcDir(
        rootProject.file("protocol/test-vectors"),
    )
    sourceSets.getByName("androidTest").assets.srcDir(
        rootProject.file("protocol/test-vectors"),
    )
}

dependencies {
    implementation(project(":core-protocol"))
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
