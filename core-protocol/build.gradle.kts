import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
}

android {
    namespace = "dev.notificationmirroring.protocol"
    compileSdk = 35
    defaultConfig { minSdk = 29 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets.named<com.android.build.api.dsl.AndroidSourceSet>("test") {
        resources.directories.add(rootProject.file("protocol/test-vectors").path)
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    api("com.google.protobuf:protobuf-javalite:4.29.3")
    testImplementation("junit:junit:4.13.2")
}
