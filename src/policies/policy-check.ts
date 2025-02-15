// SPDX-License-Identifier: MIT
/*
   Copyright (c) 2024, SCANOSS

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
 */

import { context, getOctokit } from '@actions/github';
import { promises as fs } from 'fs';
import * as core from '@actions/core';
import { getSHA } from '../utils/github.utils';
import { GitHub } from '@actions/github/lib/utils';
import * as inputs from '../app.input';
import { DefaultArtifactClient, UploadArtifactResponse } from '@actions/artifact';
import path from 'path';
import type { Endpoints } from '@octokit/types';

type ChecksCreateResponse = Endpoints['POST /repos/{owner}/{repo}/check-runs']['response'];
type CheckRun = ChecksCreateResponse['data'];

export enum CONCLUSION {
  ActionRequired = 'action_required',
  Cancelled = 'cancelled',
  Failure = 'failure',
  Neutral = 'neutral',
  Success = 'success',
  Skipped = 'skipped',
  Stale = 'stale',
  TimedOut = 'timed_out'
}

export enum STATUS {
  UNINITIALIZED = 'UNINITIALIZED',
  INITIALIZED = 'INITIALIZED',
  RUNNING = 'RUNNING',
  FINISHED = 'FINISHED'
}

export abstract class PolicyCheck {
  private readonly MAX_GH_API_CONTENT_SIZE = 65534;

  private octokit: InstanceType<typeof GitHub>;

  protected checkName: string;

  private checkRunId: number;

  private _raw?: CheckRun;

  private _status: STATUS;

  private _conclusion: CONCLUSION;

  private _firstRunId = -1;

  constructor(checkName: string) {
    this.octokit = getOctokit(inputs.GITHUB_TOKEN);
    this.checkName = checkName;
    this._status = STATUS.UNINITIALIZED;
    this._conclusion = CONCLUSION.Neutral;
    this.checkRunId = -1;
  }

  abstract artifactPolicyFileName(): string;

  abstract getPolicyName(): string;

  abstract run(): Promise<void>;

  async start(runId: number): Promise<CheckRun> {
    const result = await this.octokit.rest.checks.create({
      owner: context.repo.owner,
      repo: context.repo.repo,
      name: this.checkName,
      head_sha: getSHA()
    });

    this.checkRunId = result.data.id;
    this._raw = result.data;

    this._firstRunId = runId;

    this._status = STATUS.INITIALIZED;
    return result.data;
  }

  get name(): string {
    return this.checkName;
  }

  get conclusion(): CONCLUSION {
    return this._conclusion;
  }

  get raw(): CheckRun | undefined {
    return this._raw;
  }

  get url(): string {
    return `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${this._firstRunId}/job/${this.raw?.id}`;
  }

  initStatus(): void {
    if (this._status === STATUS.UNINITIALIZED)
      throw new Error(`Error on finish. Policy "${this.checkName}" is not created.`);

    core.debug(`Running policy check: ${this.checkName}`);
    this._status = STATUS.RUNNING;
  }

  protected async success(summary: string, text?: string): Promise<void> {
    this._conclusion = CONCLUSION.Success;
    return await this.finish(summary, text);
  }

  protected async reject(summary: string, text?: string): Promise<void> {
    if (inputs.POLICIES_HALT_ON_FAILURE) this._conclusion = CONCLUSION.Failure;
    else this._conclusion = CONCLUSION.Neutral;
    await this.finish(summary, text);
  }

  async finish(summary: string, text?: string): Promise<void> {
    core.debug(`Finish policy check: ${this.checkName}. (conclusion=${this._conclusion})`);
    this._status = STATUS.FINISHED;

    await this.updateCheck(summary, text);
  }

  async updateCheck(summary: string, text?: string): Promise<void> {
    await this.octokit.rest.checks.update({
      owner: context.repo.owner,
      repo: context.repo.repo,
      check_run_id: this.checkRunId,
      status: 'completed',
      conclusion: this._conclusion,
      output: {
        title: this.checkName,
        summary,
        text
      }
    });
  }

  protected exceedMaxGiHubApiLimit(text: string): boolean {
    return text.length > this.MAX_GH_API_CONTENT_SIZE;
  }

  protected async concatPolicyArtifactURLToPolicyCheck(details: string, artifactId: number): Promise<string> {
    const link =
      `\n\nDownload the ` +
      `[${this.getPolicyName()} Result](${context.serverUrl}/` +
      `${context.repo.owner}/${context.repo.repo}/actions/runs/` +
      `${context.runId}/artifacts/${artifactId})`;

    let text = details + link;

    if (this.exceedMaxGiHubApiLimit(text)) {
      //core.warning(`Details of ${text.length} surpass limit of ${this.MAX_GH_API_CONTENT_SIZE}`);
      core.info(`Policy check results: ${details}`);

      text =
        `Policy check details omitted from GitHub UI due to length.` +
        `See console logs for details or download the ` +
        `[${this.getPolicyName()} Result](${context.serverUrl}/` +
        `${context.repo.owner}/${context.repo.repo}/actions/runs/` +
        `${context.runId}/artifacts/${artifactId})`;
    }

    return text;
  }

  async uploadArtifact(file: string): Promise<UploadArtifactResponse> {
    await fs.writeFile(this.artifactPolicyFileName(), file);
    const artifact = new DefaultArtifactClient();
    return await artifact.uploadArtifact(
      path.basename(this.artifactPolicyFileName()),
      [this.artifactPolicyFileName()],
      path.dirname(this.artifactPolicyFileName())
    );
  }
}
