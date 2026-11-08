Releasing
=========

netguard's version comes from git tags. There is no version file and no version-bump commit.

- **Releases**: pushing an `X.Y.Z` tag on `main` releases version `X.Y.Z` to Maven Central.
- **Snapshots**: every push to `main` that changes more than docs publishes `<next minor>-SNAPSHOT`, the next minor
  version after the highest `X.Y.Z` tag in its history (after `1.10.2`, `1.11.0-SNAPSHOT`). Tags that aren't exactly
  `X.Y.Z`, like `1.12.0-rc1`, are ignored.
- Every build records its commit: in the published POM (`<scm><tag>`), and with its version as
  `1.11.0-SNAPSHOT+a1b2c3d` (`.dirty` when built with uncommitted changes).

`./gradlew :netguard:printVersion` shows the version a build would get.

## Publishing a release

1. Make sure what you want in the release is merged into `main`.
2. Tag the commit on `main` and push the tag (only maintainers can push `X.Y.Z` tags):
   ```bash
   git tag -a 1.11.0 -m "1.11.0" <commit>
   git push origin 1.11.0
   ```
3. The [release workflow](../.github/workflows/release.yml) then:
   - checks the tag is `X.Y.Z` and on `main`, and runs the native tests on it;
   - publishes the version to Maven Central, where it goes live without a manual step;
   - waits until Maven Central serves it (up to 45 minutes);
   - creates the GitHub Release, with notes from the PRs merged since the previous tag.

A patch release is the same: tag the patch version on the commit you want. It's marked as the latest GitHub Release
only if it's the highest version, and snapshots keep following the highest version.

### When it fails

Re-run the workflow from the Actions tab, or run it by hand with the tag as input; neither creates a tag. A version
on Maven Central can never be changed or published again, so the workflow checks first: if the version is already
there, it skips publishing and only creates the GitHub Release if it's missing.

If it waited 45 minutes without Maven Central serving the version, check the deployment in the
[Central Portal](https://central.sonatype.com/publishing/deployments) before re-running: while Central doesn't serve
the version yet, a re-run uploads it again.

The publishing jobs run in the `maven-central` environment, which holds the signing and Maven Central secrets and
only accepts `main` and `X.Y.Z` tags.

## Publishing to Maven Local (Development)

For local development and testing, you can publish the library to your local Maven repository:

```bash
./publish_local.sh
```

This script builds the library and publishes it to `~/.m2/repository/` as
`com.duckduckgo.netguard:netguard-android:<version>`, with the computed version or one you enter for that build
(`-PVERSION_NAME=<version>` does the same with Gradle directly).

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
