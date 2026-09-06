group = "com.vaam.flutter_sign_keypair"
version = "1.0-SNAPSHOT"

buildscript {
    val kotlinVersion = "2.3.20"
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:9.0.1")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

plugins {
    id("com.android.library")
}

android {
    namespace = "com.vaam.flutter_sign_keypair"

    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
        }
        getByName("test") {
            java.srcDirs("src/test/kotlin")
        }
        getByName("androidTest") {
            java.srcDirs("src/androidTest/kotlin")
        }
    }

    defaultConfig {
        minSdk = 24
        // Instrumented tests (src/androidTest) exercise the real AndroidKeyStore,
        // which has no JVM equivalent. Run them with:
        //   cd example/android && ./gradlew :flutter_sign_keypair:connectedDebugAndroidTest
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            all {
                it.useJUnitPlatform()

                it.outputs.upToDateWhen { false }

                it.testLogging {
                    events("passed", "skipped", "failed", "standardOut", "standardError")
                    showStandardStreams = true
                }
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    // ADR 0024's user-present key is authorised per operation, which means the
    // keymaster only releases the signature once BiometricPrompt has reported
    // success against that exact `Signature` object (via CryptoObject). There is
    // no way to drive that from Dart — `local_auth` returns a boolean, and a
    // boolean cannot authorise a keystore operation — so the prompt has to be
    // raised here, in the plugin that owns the operation.
    implementation("androidx.biometric:biometric:1.1.0")

    testImplementation("org.jetbrains.kotlin:kotlin-test")

    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("junit:junit:4.13.2")
}
