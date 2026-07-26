const assert = require("node:assert/strict");
const test = require("node:test");

const publishCodeRabbitApprovalStatus = require(
  "./publish-coderabbit-approval-status.cjs",
);

const HEAD = "a".repeat(40);

function fixture({ reviews = [], comments = [], state = "open" } = {}) {
  const statuses = [];
  const github = {
    paginate: async (method) => method(),
    rest: {
      pulls: {
        get: async () => ({ data: { state, head: { sha: HEAD } } }),
        listReviews: async () => reviews,
      },
      issues: { listComments: async () => comments },
      repos: {
        createCommitStatus: async (status) => statuses.push(status),
        getCommit: async () => ({
          data: { commit: { committer: { date: "2026-01-01T00:00:00Z" } } },
        }),
      },
    },
  };
  const context = {
    repo: { owner: "owner", repo: "repo" },
    payload: { pull_request: { number: 7, head: { sha: HEAD } } },
  };
  return { github, context, statuses, core: { info() {} } };
}

function review(state, overrides = {}) {
  return {
    id: 1,
    state,
    commit_id: HEAD,
    submitted_at: "2026-01-01T00:00:01Z",
    user: { login: "coderabbitai[bot]" },
    ...overrides,
  };
}

test("publishes success for a current-head approval", async () => {
  const setup = fixture({ reviews: [review("APPROVED")] });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "success");
  assert.deepEqual(
    setup.statuses.map(({ state }) => state),
    ["pending", "success"],
  );
  assert.equal(setup.statuses.at(-1).context, "CodeRabbit Approval");
  assert.equal(setup.statuses.at(-1).sha, HEAD);
});

test("publishes failure for current-head requested changes", async () => {
  const setup = fixture({ reviews: [review("CHANGES_REQUESTED")] });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "failure");
  assert.equal(setup.statuses.at(-1).state, "failure");
});

test("a later approval supersedes requested changes", async () => {
  const setup = fixture({
    reviews: [
      review("CHANGES_REQUESTED"),
      review("APPROVED", {
        id: 2,
        submitted_at: "2026-01-01T00:00:02Z",
      }),
    ],
  });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "success");
  assert.equal(setup.statuses.at(-1).state, "success");
});

test("dismissal or missing approval publishes the configured state", async () => {
  const setup = fixture();

  const result = await publishCodeRabbitApprovalStatus({
    ...setup,
    missingState: "failure",
  });

  assert.equal(result, "failure");
  assert.equal(setup.statuses.at(-1).state, "failure");
  assert.match(setup.statuses.at(-1).description, /dismissed/i);
});

test("stale approvals do not authorize a new head", async () => {
  const setup = fixture({
    reviews: [review("APPROVED", { commit_id: "b".repeat(40) })],
  });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "pending");
  assert.equal(setup.statuses.at(-1).state, "pending");
});

test("rate limit comments publish an error", async () => {
  const setup = fixture({
    comments: [
      {
        user: { login: "coderabbitai" },
        body: "Review limit reached",
        created_at: "2026-01-01T00:00:01Z",
      },
    ],
  });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "error");
  assert.equal(setup.statuses.at(-1).state, "error");
});

test("closed pull requests never publish success", async () => {
  const setup = fixture({ state: "closed", reviews: [review("APPROVED")] });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "error");
  assert.equal(setup.statuses.at(-1).state, "error");
});
