pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "notification-mirroring-android"
include(":app")
include(":core-notification")
include(":core-protocol")
include(":core-crypto")
include(":core-transport")
include(":notification-fixture")
