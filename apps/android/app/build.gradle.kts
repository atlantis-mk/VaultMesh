import com.android.build.api.variant.FilterConfiguration

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Review 发布通过 -P 传入版本与 ABI 拆分；本地 Debug 保持单一 APK。
val releaseVersionName = providers.gradleProperty("vaultmesh.versionName").orNull
val releaseVersionCode = providers.gradleProperty("vaultmesh.versionCode").orNull?.toInt()
val abiSplitsEnabled = providers.gradleProperty("vaultmesh.abiSplits").orNull == "true"
val releaseAbis = listOf("armeabi-v7a", "arm64-v8a", "x86_64")
val releaseKeystore = providers.environmentVariable("VAULTMESH_ANDROID_KEYSTORE_PATH").orNull

android {
    namespace = "com.vaultmesh.app"
    compileSdk = 37
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.vaultmesh.app"
        minSdk = 26
        targetSdk = 37
        versionCode = releaseVersionCode ?: 1
        versionName = releaseVersionName ?: "0.0.1-dev"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        compose = true
    }

    splits {
        abi {
            isEnable = abiSplitsEnabled
            reset()
            include(*releaseAbis.toTypedArray())
            isUniversalApk = true
        }
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = providers.environmentVariable("VAULTMESH_ANDROID_KEYSTORE_PASSWORD").get()
                keyAlias = providers.environmentVariable("VAULTMESH_ANDROID_KEY_ALIAS").get()
                keyPassword = providers.environmentVariable("VAULTMESH_ANDROID_KEY_PASSWORD").get()
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (releaseKeystore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs.useLegacyPackaging = false
        // 依赖自带的 32 位 x86 库没有对应 Rust runtime，打入 APK 会让 x86 设备选中不可用 ABI。
        jniLibs.excludes += "/lib/x86/**"
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

// universal 使用 0，其余 ABI 使用稳定个位，使同一版本各 ABI 的 versionCode 互不冲突。
androidComponents {
    onVariants { variant ->
        variant.outputs.forEach { output ->
            val abi = output.filters.find { it.filterType == FilterConfiguration.FilterType.ABI }?.identifier
            if (abi != null) {
                val base = output.versionCode.orNull ?: 1
                output.versionCode.set(base + releaseAbis.indexOf(abi) + 1)
            }
        }
    }
}

val buildRustDebug = tasks.register<Exec>("buildRustDebug") {
    workingDir(rootProject.projectDir)
    commandLine("bash", "scripts/build-rust.sh", "debug")
}

val buildRustRelease = tasks.register<Exec>("buildRustRelease") {
    workingDir(rootProject.projectDir)
    commandLine("bash", "scripts/build-rust.sh", "release")
}

tasks.matching { it.name == "mergeDebugJniLibFolders" }.configureEach {
    dependsOn(buildRustDebug)
}
tasks.matching { it.name == "mergeReleaseJniLibFolders" }.configureEach {
    dependsOn(buildRustRelease)
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.08.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.11.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("com.google.android.gms:play-services-auth-api-phone:18.3.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    // Align Espresso with runner/core; the transitive 3.5.0 uses removed InputManager reflection.
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.test:core-ktx:1.7.0")
    androidTestImplementation("androidx.test.uiautomator:uiautomator:2.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    testImplementation("junit:junit:4.13.2")
}
