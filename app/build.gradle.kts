import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val localSigningProperties = Properties().apply {
    val propertiesFile = rootProject.file(".signing/signing.properties")
    if (propertiesFile.isFile) {
        propertiesFile.inputStream().use(::load)
    }
}

fun signingValue(environmentName: String, propertyName: String): String? =
    System.getenv(environmentName)?.takeIf(String::isNotBlank)
        ?: localSigningProperties.getProperty(propertyName)?.takeIf(String::isNotBlank)

val signingStoreFile = signingValue("ANDROID_SIGNING_STORE_FILE", "storeFile")
val signingStorePassword = signingValue("ANDROID_SIGNING_STORE_PASSWORD", "storePassword")
val signingKeyAlias = signingValue("ANDROID_SIGNING_KEY_ALIAS", "keyAlias")
val signingKeyPassword = signingValue("ANDROID_SIGNING_KEY_PASSWORD", "keyPassword")
val fixedSigningValues = listOf(
    signingStoreFile,
    signingStorePassword,
    signingKeyAlias,
    signingKeyPassword,
)
val hasFixedSigningIdentity = fixedSigningValues.all { it != null }
require(fixedSigningValues.none { it != null } || hasFixedSigningIdentity) {
    "Fixed Android signing configuration is incomplete; refusing to select a fallback identity"
}

android {
    namespace = "dev.notificationmirroring.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.notificationmirroring.android"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-dev"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    val fixedSigningConfig = if (hasFixedSigningIdentity) {
        signingConfigs.create("fixed") {
            storeFile = rootProject.file(requireNotNull(signingStoreFile))
            storePassword = requireNotNull(signingStorePassword)
            keyAlias = requireNotNull(signingKeyAlias)
            keyPassword = requireNotNull(signingKeyPassword)
        }
    } else {
        null
    }

    buildTypes {
        getByName("debug") {
            fixedSigningConfig?.let { signingConfig = it }
        }
        getByName("release") {
            fixedSigningConfig?.let { signingConfig = it }
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation(project(":core-notification"))
    implementation(project(":core-protocol"))
    implementation(project(":core-crypto"))
    implementation(project(":core-storage"))
    implementation(project(":core-transport"))

    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
}
