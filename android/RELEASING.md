Releasing
========

## Publishing to Maven Local (Development)

For local development and testing, you can publish the library to your local Maven repository:

```bash
./publish_local.sh
```

This script will build and publish the library to `~/.m2/repository/` as `com.duckduckgo.netguard:netguard-android:<version>`.

To use the local version in another project, add `mavenLocal()` to your repositories:

```gradle
repositories {
    mavenLocal()  // Add this before other repositories
    // ... other repositories
}

dependencies {
    implementation 'com.duckduckgo.netguard:netguard-android:<version>'
}
```

## Publishing to Maven Central (Production)

1. Change the version in `version.properties` to a non-SNAPSHOT version.
2. `git commit -am "Release X.Y.Z"` (where X.Y.Z is the new version)
3. `git tag -a X.Y.X -m "X.Y.Z"` (where X.Y.Z is the new version)
4. `git push && git push --tags`
5. Update the `version.properties` to the next SNAPSHOT version.
6. `git commit -am "Prepare next development version."`
7. `git push`

Alternatively, you can use the `fastlane release` to do this for you.
