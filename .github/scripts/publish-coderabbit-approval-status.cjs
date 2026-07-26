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
  const committedAtByHead = new Map();
  await publishStatus(
    github,
    context,
    statusSha,
    "pending",
    "Waiting for current-head CodeRabbit approval",
  );

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
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

      const committedAt = committedAtByHead.has(headSha)
        ? Promise.resolve(committedAtByHead.get(headSha))
        : github.rest.repos
            .getCommit({ owner, repo, ref: headSha })
            .then((response) => {
              const value = response.data.commit.committer.date;
              committedAtByHead.set(headSha, value);
              return value;
            });
      const [reviews, comments, headCommittedAt] = await Promise.all([
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
        committedAt,
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
      if (review?.state === "DISMISSED") {
        await publishStatus(
          github,
          context,
          statusSha,
          "failure",
          "Current-head CodeRabbit approval was dismissed",
        );
        return "failure";
      }

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
    } catch (error) {
      core.error(error instanceof Error ? error.stack || error.message : String(error));
      try {
        await publishStatus(
          github,
          context,
          statusSha,
          "error",
          "CodeRabbit status evaluation failed; inspect workflow logs",
        );
      } catch (statusError) {
        core.error(
          statusError instanceof Error
            ? statusError.stack || statusError.message
            : String(statusError),
        );
        throw statusError;
      }
      return "error";
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
