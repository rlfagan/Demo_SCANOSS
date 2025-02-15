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

import * as core from '@actions/core';

export const POLICIES = core.getInput('policies');
export const POLICIES_HALT_ON_FAILURE = core.getInput('policies.halt_on_failure') === 'true';
export const DEPENDENCIES_ENABLED = core.getInput('dependencies.enabled') === 'true';
export const DEPENDENCIES_SCOPE = core.getInput('dependencies.scope');
export const DEPENDENCY_SCOPE_EXCLUDE = core.getInput('dependencies.scope.exclude');
export const DEPENDENCY_SCOPE_INCLUDE = core.getInput('dependencies.scope.include');
export const API_KEY = core.getInput('api.key');
export const API_URL = core.getInput('api.url');
export const OUTPUT_FILEPATH = core.getInput('output.filepath');
export const GITHUB_TOKEN = core.getInput('github.token');
export const COPYLEFT_LICENSE_INCLUDE = core.getInput('licenses.copyleft.include');
export const COPYLEFT_LICENSE_EXCLUDE = core.getInput('licenses.copyleft.exclude');
export const COPYLEFT_LICENSE_EXPLICIT = core.getInput('licenses.copyleft.explicit');
export const REPO_DIR = process.env.GITHUB_WORKSPACE as string;
export const RUNTIME_CONTAINER = core.getInput('runtimeContainer') || 'ghcr.io/scanoss/scanoss-py:v1.19.0';
export const SKIP_SNIPPETS = core.getInput('skipSnippets') === 'true';
export const SCAN_FILES = core.getInput('scanFiles') === 'true';
export const SCANOSS_SETTINGS = core.getInput('scanossSettings') === 'true';
export const SETTINGS_FILE_PATH = core.getInput('settingsFilepath') || 'scanoss.json';
export const EXECUTABLE = 'docker';
