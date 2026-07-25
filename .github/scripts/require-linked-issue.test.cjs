const assert = require("node:assert/strict");
const test = require("node:test");

const enforceLinkedIssue = require("./require-linked-issue.cjs");
const {
  COMMENT_MARKER,
  currentRepositoryReferences,
} = enforceLinkedIssue;

function harness(nodes, comments = []) {
  const events = { comments: [], closed: [], failures: [], info: [] };
  const github = {
    graphql: async () => ({
      repository: {
        pullRequest: { closingIssuesReferences: { nodes } },
      },
    }),
    paginate: async () => comments,
    rest: {
      issues: {
        listComments: async () => ({ data: comments }),
        createComment: async (input) => events.comments.push(input),
      },
      pulls: {
        update: async (input) => events.closed.push(input),
      },
    },
  };
  const context = {
    repo: { owner: "Success6666", repo: "agent-runtime-governance" },
    payload: { pull_request: { number: 7 } },
  };
  const core = {
    info: (message) => events.info.push(message),
    setFailed: (message) => events.failures.push(message),
  };
  return { github, context, core, events };
}

test("keeps a PR linked to an issue in the current repository", async () => {
  const state = harness([
    {
      number: 42,
      repository: { nameWithOwner: "Success6666/agent-runtime-governance" },
    },
  ]);

  await enforceLinkedIssue(state);

  assert.equal(state.events.closed.length, 0);
  assert.equal(state.events.failures.length, 0);
  assert.match(state.events.info[0], /#42/);
});

test("closes a PR without a linked issue", async () => {
  const state = harness([]);

  await enforceLinkedIssue(state);

  assert.equal(state.events.comments.length, 1);
  assert.match(state.events.comments[0].body, /Fixes #123/);
  assert.equal(state.events.closed[0].state, "closed");
  assert.equal(state.events.failures.length, 1);
});

test("does not accept an issue from another repository", async () => {
  const nodes = [
    { number: 42, repository: { nameWithOwner: "someone/else" } },
  ];

  assert.deepEqual(
    currentRepositoryReferences(
      nodes,
      "Success6666",
      "agent-runtime-governance",
    ),
    [],
  );
});

test("does not post the same closure comment twice", async () => {
  const state = harness([], [{ body: `${COMMENT_MARKER}\nalready posted` }]);

  await enforceLinkedIssue(state);

  assert.equal(state.events.comments.length, 0);
  assert.equal(state.events.closed.length, 1);
});
