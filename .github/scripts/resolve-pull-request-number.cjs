async function resolvePullRequestNumber({ github, context }) {
  const directNumber = context.payload.pull_request?.number;
  if (directNumber) {
    return directNumber;
  }

  const workflowRun = context.payload.workflow_run;
  if (!workflowRun) {
    throw new Error("pull request context is missing from the event payload");
  }

  const embeddedPulls = (workflowRun.pull_requests || []).filter(
    (pullRequest) => Number.isInteger(pullRequest?.number),
  );
  if (embeddedPulls.length === 1) {
    return embeddedPulls[0].number;
  }

  if (!workflowRun.head_sha) {
    throw new Error("workflow run head SHA is missing from the event payload");
  }

  const response = await github.rest.repos.listPullRequestsAssociatedWithCommit({
    ...context.repo,
    commit_sha: workflowRun.head_sha,
  });
  const repositoryName = `${context.repo.owner}/${context.repo.repo}`.toLowerCase();
  const candidates = response.data.filter(
    (pullRequest) =>
      pullRequest.state === "open" &&
      pullRequest.head?.sha === workflowRun.head_sha &&
      String(pullRequest.base?.repo?.full_name || "").toLowerCase() ===
        repositoryName,
  );

  if (candidates.length !== 1) {
    throw new Error(
      `expected one open pull request for workflow run ${workflowRun.id}, found ${candidates.length}`,
    );
  }
  return candidates[0].number;
}

module.exports = resolvePullRequestNumber;
