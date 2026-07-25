const assert = require("node:assert/strict");
const test = require("node:test");

const verifyCodeRabbitReview = require("./verify-coderabbit-review.cjs");
const {
  isCodeRabbit,
  isCurrentRateLimitComment,
  latestReviewForHead,
} = verifyCodeRabbitReview;

function review(state, commitId = "current-sha", submittedAt = "2026-07-25T00:00:00Z") {
  return {
    id: Date.parse(submittedAt),
    state,
    commit_id: commitId,
    submitted_at: submittedAt,
    user: { login: "coderabbitai" },
  };
}

function harness({ reviews = [], comments = [], pullState = "open" } = {}) {
  const failures = [];
  const info = [];
  const github = {
    paginate: async (endpoint) =>
      endpoint === github.rest.pulls.listReviews ? reviews : comments,
    rest: {
      pulls: {
        get: async () => ({
          data: {
            state: pullState,
            head: { sha: "current-sha" },
          },
        }),
        listReviews: async () => ({ data: reviews }),
      },
      issues: {
        listComments: async () => ({ data: comments }),
      },
      repos: {
        getCommit: async () => ({
          data: { commit: { committer: { date: "2026-07-25T00:00:00Z" } } },
        }),
      },
    },
  };
  const context = {
    repo: { owner: "owner", repo: "repo" },
    payload: { pull_request: { number: 7 } },
  };
  const core = {
    info: (message) => info.push(message),
    setFailed: (message) => failures.push(message),
  };
  return { github, context, core, failures, info };
}

test("recognizes CodeRabbit bot login variants only", () => {
  assert.equal(isCodeRabbit("coderabbitai"), true);
  assert.equal(isCodeRabbit("coderabbitai[bot]"), true);
  assert.equal(isCodeRabbit("not-coderabbitai"), false);
});

test("accepts only an approval for the current head commit", async () => {
  const state = harness({
    reviews: [
      review("APPROVED", "old-sha", "2026-07-25T00:00:00Z"),
      review("APPROVED", "current-sha", "2026-07-25T00:01:00Z"),
    ],
  });

  await verifyCodeRabbitReview(state);

  assert.equal(state.failures.length, 0);
  assert.match(state.info[0], /approved/);
});

test("fails when CodeRabbit requests changes", async () => {
  const state = harness({ reviews: [review("CHANGES_REQUESTED")] });

  await verifyCodeRabbitReview(state);

  assert.match(state.failures[0], /requested changes/);
});

test("fails when only a stale review exists", async () => {
  const state = harness({ reviews: [review("APPROVED", "old-sha")] });

  await verifyCodeRabbitReview(state);

  assert.match(state.failures[0], /before timeout/);
});

test("fails closed for a current CodeRabbit review limit", async () => {
  const comment = {
    user: { login: "coderabbitai" },
    body: "Review limit reached. We couldn't start this review.",
    created_at: "2026-07-25T00:01:00Z",
  };
  const state = harness({ comments: [comment] });

  await verifyCodeRabbitReview(state);

  assert.equal(
    isCurrentRateLimitComment(comment, "2026-07-25T00:00:00Z"),
    true,
  );
  assert.match(state.failures[0], /review limit/);
});

test("ignores an old rate-limit comment after a new commit", async () => {
  const comment = {
    user: { login: "coderabbitai" },
    body: "Review limit reached.",
    created_at: "2026-07-24T23:59:00Z",
  };
  const state = harness({ comments: [comment] });

  await verifyCodeRabbitReview(state);

  assert.equal(
    isCurrentRateLimitComment(comment, "2026-07-25T00:00:00Z"),
    false,
  );
  assert.match(state.failures[0], /before timeout/);
});

test("does not let another user spoof a rate-limit failure", async () => {
  const comment = {
    user: { login: "contributor" },
    body: "Review limit reached.",
    created_at: "2026-07-25T00:01:00Z",
  };
  const state = harness({ comments: [comment] });

  await verifyCodeRabbitReview(state);

  assert.match(state.failures[0], /before timeout/);
});

test("uses the latest current-head review", () => {
  const latest = latestReviewForHead(
    [
      review("CHANGES_REQUESTED", "current-sha", "2026-07-25T00:00:00Z"),
      review("APPROVED", "current-sha", "2026-07-25T00:01:00Z"),
    ],
    "current-sha",
  );

  assert.equal(latest.state, "APPROVED");
});

test("fails immediately when the PR was already closed", async () => {
  const state = harness({ pullState: "closed" });

  await verifyCodeRabbitReview(state);

  assert.match(state.failures[0], /closed before/);
});
