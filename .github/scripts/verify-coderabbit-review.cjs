function isCodeRabbit(login) {
  return String(login || "")
    .toLowerCase()
    .replace(/\[bot\]$/, "") === "coderabbitai";
}

function latestReviewForHead(reviews, headSha) {
  return (reviews || [])
    .filter(
      (review) =>
        isCodeRabbit(review?.user?.login) &&
        review.commit_id === headSha &&
        ["APPROVED", "CHANGES_REQUESTED", "DISMISSED"].includes(review.state),
    )
    .sort((left, right) => {
      const timeDifference =
        Date.parse(left.submitted_at || 0) - Date.parse(right.submitted_at || 0);
      return timeDifference || Number(left.id || 0) - Number(right.id || 0);
    })
    .at(-1);
}

function isCurrentRateLimitComment(comment, headCommittedAt) {
  if (!isCodeRabbit(comment?.user?.login)) {
    return false;
  }
  const body = String(comment.body || "").toLowerCase();
  const timestamp = Date.parse(comment.updated_at || comment.created_at || 0);
  return (
    timestamp >= Date.parse(headCommittedAt) &&
    (body.includes("review limit reached") ||
      body.includes("couldn't start this review") ||
      body.includes("rate limited by coderabbit.ai"))
  );
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function verifyCodeRabbitReview({
  github,
  context,
  core,
  maxAttempts = 1,
  intervalMs = 0,
  wait = sleep,
}) {
  const { owner, repo } = context.repo;
  const pullNumber = context.payload.pull_request?.number;
  if (!pullNumber) {
    throw new Error("pull request number is missing from the event payload");
  }

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    const pullResponse = await github.rest.pulls.get({
      owner,
      repo,
      pull_number: pullNumber,
    });
    const pullRequest = pullResponse.data;
    const headSha = pullRequest.head.sha;
    if (pullRequest.state === "closed") {
      core.setFailed("pull request closed before CodeRabbit approval");
      return;
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
      core.info("CodeRabbit approved the current commit");
      return;
    }
    if (review?.state === "CHANGES_REQUESTED") {
      core.setFailed("CodeRabbit requested changes on the current commit");
      return;
    }

    const headCommittedAt = commitResponse.data.commit.committer.date;
    if (
      comments.some((comment) =>
        isCurrentRateLimitComment(comment, headCommittedAt),
      )
    ) {
      core.setFailed("CodeRabbit review was skipped because of a review limit");
      return;
    }

    if (attempt < maxAttempts) {
      core.info(
        `waiting for CodeRabbit approval (${attempt}/${maxAttempts})`,
      );
      await wait(intervalMs);
    }
  }

  core.setFailed("CodeRabbit did not approve the current commit before timeout");
}

module.exports = verifyCodeRabbitReview;
module.exports.isCodeRabbit = isCodeRabbit;
module.exports.isCurrentRateLimitComment = isCurrentRateLimitComment;
module.exports.latestReviewForHead = latestReviewForHead;
