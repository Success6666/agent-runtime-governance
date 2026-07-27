const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const publishCodeRabbitApprovalStatus = require(
  "./publish-coderabbit-approval-status.cjs",
);

const HEAD = "a".repeat(40);

test("workflow keeps the CodeRabbit handoff from cancelling the current-head check", () => {
  const workflow = fs.readFileSync(
    path.resolve(
      __dirname,
      "..",
      "workflows",
      "coderabbit-approval-status.yml",
    ),
    "utf8",
  );

  assert.match(workflow, /}}-\$\{\{ github\.event_name \}\}/);
  assert.match(
    workflow,
    /cancel-in-progress:\s*\$\{\{ github\.event_name == 'pull_request_target' \}\}/,
  );
});

function fixture({
  reviews = [],
  comments = [],
  state = "open",
  currentHead = HEAD,
  eventHead = HEAD,
  pullError,
} = {}) {
  const statuses = [];
  const errors = [];
  let commitLookups = 0;
  const github = {
    paginate: async (method) => method(),
    rest: {
      pulls: {
        get: async () => {
          if (pullError) {
            throw pullError;
          }
          return { data: { state, head: { sha: currentHead } } };
        },
        listReviews: async () => reviews,
      },
      issues: { listComments: async () => comments },
      repos: {
        createCommitStatus: async (status) => statuses.push(status),
        getCommit: async () => {
          commitLookups += 1;
          return {
            data: { commit: { committer: { date: "2026-01-01T00:00:00Z" } } },
          };
        },
      },
    },
  };
  const context = {
    repo: { owner: "owner", repo: "repo" },
    payload: { pull_request: { number: 7, head: { sha: eventHead } } },
  };
  return {
    github,
    context,
    statuses,
    errors,
    get commitLookups() {
      return commitLookups;
    },
    core: { info() {}, error(value) { errors.push(value); } },
  };
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
      review("APPROVED", {
        id: 2,
        submitted_at: "2026-01-01T00:00:02Z",
      }),
      review("CHANGES_REQUESTED"),
    ],
  });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "success");
  assert.equal(setup.statuses.at(-1).state, "success");
});

test("dismissal remains failure until a newer approval", async () => {
  const dismissed = review("DISMISSED", {
    id: 2,
    submitted_at: "2026-01-01T00:00:02Z",
  });
  const setup = fixture({ reviews: [review("APPROVED"), dismissed] });

  const dismissedResult = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(dismissedResult, "failure");
  assert.equal(setup.statuses.at(-1).state, "failure");
  assert.match(setup.statuses.at(-1).description, /dismissed/i);

  const approved = fixture({
    reviews: [
      dismissed,
      review("APPROVED", {
        id: 3,
        submitted_at: "2026-01-01T00:00:03Z",
      }),
    ],
  });

  const approvedResult = await publishCodeRabbitApprovalStatus(approved);

  assert.equal(approvedResult, "success");
});

test("missing approval publishes the configured state", async () => {
  const setup = fixture();

  const result = await publishCodeRabbitApprovalStatus({
    ...setup,
    missingState: "failure",
  });

  assert.equal(result, "failure");
  assert.equal(setup.statuses.at(-1).state, "failure");
  assert.match(setup.statuses.at(-1).description, /dismissed/i);
});

test("a new head receives a new pending status", async () => {
  const nextHead = "b".repeat(40);
  const setup = fixture({ eventHead: HEAD, currentHead: nextHead });

  const result = await publishCodeRabbitApprovalStatus(setup);

  assert.equal(result, "pending");
  assert.deepEqual(
    setup.statuses.map(({ sha, state }) => [sha, state]),
    [
      [nextHead, "pending"],
      [nextHead, "pending"],
    ],
  );
});

test("commit timestamps are cached while polling the same head", async () => {
  const setup = fixture();

  await publishCodeRabbitApprovalStatus({
    ...setup,
    maxAttempts: 3,
    wait: async () => {},
  });

  assert.equal(setup.commitLookups, 1);
});

test("the workflow fails closed when the current head cannot be read", async () => {
  const setup = fixture({ pullError: new Error("network unavailable") });

  await assert.rejects(
    publishCodeRabbitApprovalStatus(setup),
    /network unavailable/,
  );
  assert.equal(setup.statuses.length, 0);
  assert.match(setup.errors.at(-1), /network unavailable/);
});

test("accepts an explicit pull request number for workflow-run events", async () => {
  const setup = fixture({ reviews: [review("APPROVED")] });
  setup.context.payload = { workflow_run: { id: 101 } };

  const result = await publishCodeRabbitApprovalStatus({
    ...setup,
    pullNumber: 22,
  });

  assert.equal(result, "success");
  assert.equal(setup.statuses.at(-1).sha, HEAD);
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
