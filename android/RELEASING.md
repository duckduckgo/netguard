Releasing
========

1. Change the version in `gradle.properties` to a non-SNAPSHOT version.
2. `git commit -am "Release X.Y.Z"` (where X.Y.Z is the new version)
3. `git tag -a X.Y.X -m "X.Y.Z"` (where X.Y.Z is the new version)
4. `git push && git push --tags`
5. Update the `gradle.properties` to the next SNAPSHOT version.
6. `git commit -am "Prepare next development version."`
7. `git push`
8. Visit [Sonatype Nexus](https://s01.oss.sonatype.org/) and promote the artifact.