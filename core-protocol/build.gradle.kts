plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "dev.notificationmirroring.protocol"
    compileSdk = 35
    defaultConfig { minSdk = 29 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    sourceSets.getByName("test").resources.srcDir(
        rootProject.file("protocol/test-vectors"),
    )
}

dependencies {
    api("com.google.protobuf:protobuf-javalite:4.29.3")
    testImplementation("junit:junit:4.13.2")
}
