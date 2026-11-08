# release-status

Generates the page at https://duckduckgo.github.io/netguard/, showing what's published: for each commit on `main`,
whether it's in the snapshot, in which release on Maven Central, and since which DuckDuckGo Android app release it's
on users' phones.

```bash
node tools/release-status/generate.js --open
```

Node 18 or newer, no dependencies. It reads:

- git: `main`'s last 200 commits (`origin/main` when there is one, else `--ref`) and the `X.Y.Z` tags;
- Maven Central: the releases, and the latest snapshot with the commit it was built from (recorded in its POM since
  tag-driven versions; older builds say "not recorded");
- the app's store releases (duckduckgo/Android's GitHub Releases) and the netguard version each pins in its
  `versions.properties`. Set `GITHUB_TOKEN` if the GitHub API rate limit gets in the way.

A source that can't be read shows as such on the page instead of stopping it. The page is written to
`tools/release-status/build/index.html` (`--out` to change it); `--summary <file>` appends the pipeline as a markdown
table, which the [overview workflow](../../.github/workflows/overview.yml) puts in each run's summary.

Tests: `node --test tools/release-status/test/*.test.js`
