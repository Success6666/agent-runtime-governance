const COMMENT_MARKER = "<!-- linked-issue-required -->";

function currentRepositoryReferences(nodes, owner, repo) {
  const expected = `${owner}/${repo}`.toLowerCase();
  return (nodes || []).filter(
    (node) => node?.repository?.nameWithOwner?.toLowerCase() === expected,
  );
}

async function enforceLinkedIssue({ github, context, core }) {
  const { owner, repo } = context.repo;
  const pullNumber = context.payload.pull_request.number;
  const result = await github.graphql(
    `query($owner: String!, $repo: String!, $number: Int!) {
      repository(owner: $owner, name: $repo) {
        pullRequest(number: $number) {
          closingIssuesReferences(first: 100) {
            nodes {
              number
              repository { nameWithOwner }
            }
          }
        }
      }
    }`,
    { owner, repo, number: pullNumber },
  );

  const pullRequest = result?.repository?.pullRequest;
  if (!pullRequest) {
    throw new Error(`pull request #${pullNumber} was not found`);
  }

  const linkedIssues = currentRepositoryReferences(
    pullRequest.closingIssuesReferences?.nodes,
    owner,
    repo,
  );
  if (linkedIssues.length > 0) {
    core.info(
      `linked issue found: ${linkedIssues.map((issue) => `#${issue.number}`).join(", ")}`,
    );
    return;
  }

  const comments = await github.paginate(github.rest.issues.listComments, {
    owner,
    repo,
    issue_number: pullNumber,
    per_page: 100,
  });
  if (!comments.some((comment) => comment.body?.includes(COMMENT_MARKER))) {
    await github.rest.issues.createComment({
      owner,
      repo,
      issue_number: pullNumber,
      body: `${COMMENT_MARKER}\nThis PR was automatically closed because it does not link an existing issue in this repository. Add a closing keyword such as \`Fixes #123\` to the PR description, then reopen it.`,
    });
  }

  await github.rest.pulls.update({
    owner,
    repo,
    pull_number: pullNumber,
    state: "closed",
  });
  core.setFailed("pull request must link an existing repository issue");
}

module.exports = enforceLinkedIssue;
module.exports.currentRepositoryReferences = currentRepositoryReferences;
module.exports.COMMENT_MARKER = COMMENT_MARKER;
