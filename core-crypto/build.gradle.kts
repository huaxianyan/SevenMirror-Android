import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
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

    sourceSets.named<com.android.build.api.dsl.AndroidSourceSet>("test") {
        resources.directories.add(rootProject.file("protocol/test-vectors").path)
    }
    sourceSets.named<com.android.build.api.dsl.AndroidSourceSet>("androidTest") {
        assets.directories.add(rootProject.file("protocol/test-vectors").path)
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(project(":core-protocol"))
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
