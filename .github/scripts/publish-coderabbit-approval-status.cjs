const {
  isCurrentRateLimitComment,
  latestReviewForHead,
} = require("./verify-coderabbit-review.cjs");

const STATUS_CONTEXT = "CodeRabbit Approval";

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function publishStatus(github, context, sha, state, description) {
  await github.rest.repos.createCommitStatus({
    ...context.repo,
    sha,
    state,
    context: STATUS_CONTEXT,
    description,
  });
}

async function publishCodeRabbitApprovalStatus({
  github,
  context,
  core,
  maxAttempts = 1,
  intervalMs = 0,
  missingState = "pending",
  wait = sleep,
}) {
  const { owner, repo } = context.repo;
  const pullNumber = context.payload.pull_request?.number;
  if (!pullNumber) {
    throw new Error("pull request number is missing from the event payload");
  }

  let statusSha = context.payload.pull_request.head.sha;
  await publishStatus(
    github,
    context,
    statusSha,
    "pending",
    "Waiting for current-head CodeRabbit approval",
  );

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const pullResponse = await github.rest.pulls.get({
      owner,
      repo,
      pull_number: pullNumber,
    });
    const pullRequest = pullResponse.data;
    const headSha = pullRequest.head.sha;

    if (headSha !== statusSha) {
      statusSha = headSha;
      await publishStatus(
        github,
        context,
        statusSha,
        "pending",
        "Waiting for current-head CodeRabbit approval",
      );
    }

    if (pullRequest.state === "closed") {
      await publishStatus(
        github,
        context,
        statusSha,
        "error",
        "Pull request closed before CodeRabbit approval",
      );
      return "error";
    }

    const [reviews, comments, commitResponse] = await Promise.all([
      github.paginate(github.rest.pulls.listReviews, {
        owner,
        repo,
        pull_number: pullNumber,
        per_page: 100,
      }),
      github.paginate(github.rest.issues.listComments, {
        owner,
        repo,
        issue_number: pullNumber,
        per_page: 100,
      }),
      github.rest.repos.getCommit({ owner, repo, ref: headSha }),
    ]);

    const review = latestReviewForHead(reviews, headSha);
    if (review?.state === "APPROVED") {
      await publishStatus(
        github,
        context,
        statusSha,
        "success",
        "CodeRabbit approved the current commit",
      );
      return "success";
    }
    if (review?.state === "CHANGES_REQUESTED") {
      await publishStatus(
        github,
        context,
        statusSha,
        "failure",
        "CodeRabbit requested changes on the current commit",
      );
      return "failure";
    }

    const headCommittedAt = commitResponse.data.commit.committer.date;
    if (
      comments.some((comment) =>
        isCurrentRateLimitComment(comment, headCommittedAt),
      )
    ) {
      await publishStatus(
        github,
        context,
        statusSha,
        "error",
        "CodeRabbit review was skipped because of a review limit",
      );
      return "error";
    }

    if (attempt < maxAttempts) {
      core.info(
        `waiting for CodeRabbit approval (${attempt}/${maxAttempts})`,
      );
      await wait(intervalMs);
    }
  }

  const description =
    missingState === "failure"
      ? "Current-head CodeRabbit approval was dismissed"
      : "Current-head CodeRabbit approval is pending";
  await publishStatus(
    github,
    context,
    statusSha,
    missingState,
    description,
  );
  return missingState;
}

module.exports = publishCodeRabbitApprovalStatus;
module.exports.STATUS_CONTEXT = STATUS_CONTEXT;
