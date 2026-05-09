pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

// Gradle 8.x не умеет сам качать тулчейны без явного резолвера.
// foojay-resolver-convention подтягивает JDK с api.foojay.io если в системе
// нет нужной версии. На CI / у разработчиков в Android Studio этого может
// и не понадобиться (JBR обычно подходит), но без плагина любая попытка
// сборки через jvmToolchain(N) роняется с «No locally installed toolchains».
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "IPbrowse"
include(":app")
