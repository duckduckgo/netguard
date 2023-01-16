Releasing
========

1. Change the version in `version.properties` to a non-SNAPSHOT version.
2. `git commit -am "Release X.Y.Z"` (where X.Y.Z is the new version)
3. `git tag -a X.Y.X -m "X.Y.Z"` (where X.Y.Z is the new version)
4. `git push && git push --tags`
5. Update the `version.properties` to the next SNAPSHOT version.
6. `git commit -am "Prepare next development version."`
7. `git push`

Alternatively, you can use the `fastlane release` to do this for you.
