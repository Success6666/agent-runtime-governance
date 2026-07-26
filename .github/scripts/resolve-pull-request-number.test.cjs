const assert = require("node:assert/strict");
const test = require("node:test");

const resolvePullRequestNumber = require("./resolve-pull-request-number.cjs");

function fixture(payload, associatedPulls = []) {
  let associationLookups = 0;
  return {
    context: {
      repo: { owner: "owner", repo: "repo" },
      payload,
    },
    github: {
      rest: {
        repos: {
          listPullRequestsAssociatedWithCommit: async () => {
            associationLookups += 1;
            return { data: associatedPulls };
          },
        },
      },
    },
    get associationLookups() {
      return associationLookups;
    },
  };
}

test("uses the pull request target payload directly", async () => {
  const setup = fixture({ pull_request: { number: 22 } });

  assert.equal(await resolvePullRequestNumber(setup), 22);
  assert.equal(setup.associationLookups, 0);
});

test("uses the single pull request attached to a workflow run", async () => {
  const setup = fixture({
    workflow_run: {
      id: 101,
      head_sha: "a".repeat(40),
      pull_requests: [{ number: 22 }],
    },
  });

  assert.equal(await resolvePullRequestNumber(setup), 22);
  assert.equal(setup.associationLookups, 0);
});

test("resolves a fork workflow run through its associated commit", async () => {
  const headSha = "b".repeat(40);
  const setup = fixture(
    { workflow_run: { id: 102, head_sha: headSha, pull_requests: [] } },
    [
      {
        number: 23,
        state: "open",
        head: { sha: headSha },
        base: { repo: { full_name: "owner/repo" } },
      },
    ],
  );

  assert.equal(await resolvePullRequestNumber(setup), 23);
  assert.equal(setup.associationLookups, 1);
});

test("rejects ambiguous associated pull requests", async () => {
  const headSha = "c".repeat(40);
  const candidate = {
    state: "open",
    head: { sha: headSha },
    base: { repo: { full_name: "owner/repo" } },
  };
  const setup = fixture(
    { workflow_run: { id: 103, head_sha: headSha, pull_requests: [] } },
    [
      { ...candidate, number: 24 },
      { ...candidate, number: 25 },
    ],
  );

  await assert.rejects(
    resolvePullRequestNumber(setup),
    /expected one open pull request.*found 2/,
  );
});

test("rejects events without a pull request context", async () => {
  const setup = fixture({});

  await assert.rejects(
    resolvePullRequestNumber(setup),
    /pull request context is missing/,
  );
});
