#!/usr/bin/python3

# Copyright 2025 IBM, Inc.
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This script was generated with the assistance of an AI language model.
#
# This is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License version 2.1, as published by
# the Free Software Foundation.  See file COPYING.

import argparse
import copy
import itertools
import json
import logging
import os
import re
import signal
import sys

from datetime import datetime, timedelta, timezone
from getpass import getuser
from os.path import expanduser

import git # https://github.com/gitpython-developers/gitpython
import redminelib # https://pypi.org/project/python-redmine/
import requests

GITHUB_TOKEN = None
try:
    with open(expanduser("~/.github_token")) as f:
        GITHUB_TOKEN = f.read().strip()
except FileNotFoundError:
    pass
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", GITHUB_TOKEN)

GITHUB_USER = os.getenv("GITHUB_USER", os.getenv("GITHUB_USER", getuser()))

GITHUB_ORG="ceph"
GITHUB_REPO="ceph"

REDMINE_CUSTOM_FIELD_ID_PULL_REQUEST_ID = 21
REDMINE_CUSTOM_FIELD_ID_MERGE_COMMIT = 33
REDMINE_CUSTOM_FIELD_ID_FIXED_IN = 34
REDMINE_CUSTOM_FIELD_ID_RELEASED_IN = 35
REDMINE_CUSTOM_FIELD_ID_UPKEEP_TIMESTAMP = 37

REDMINE_STATUS_ID_PENDING_BACKPORT = 14
REDMINE_STATUS_ID_RESOLVED = 3

REDMINE_ENDPOINT = "https://tracker.ceph.com"
REDMINE_API_KEY = None
try:
    with open(expanduser("~/.redmine_key")) as f:
        REDMINE_API_KEY = f.read().strip()
except FileNotFoundError:
    pass
REDMINE_API_KEY = os.getenv("REDMINE_API_KEY", REDMINE_API_KEY)

log = logging.getLogger(__name__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.INFO)

def gitauth():
    return (GITHUB_USER, GITHUB_TOKEN)

class IssueUpdate:
    def __init__(self, issue, github_session, git_repo):
        self.issue = issue
        self.update_payload = {}
        self.github_session = github_session
        self.git_repo = git_repo
        self._pr_cache = {}
        self.has_changes = False # New flag to track if changes are made

    def get_custom_field(self, field_id):
        """ Get the custom field, first from update_payload otherwise issue """
        custom_fields = self.update_payload.setdefault("custom_fields", [])
        for field in custom_fields:
            if field.get('id') == field_id:
                return field['value']
        cf = self.issue.custom_fields.get(field_id)
        try:
            return cf.value if cf else None
        except redminelib.exceptions.ResourceAttrError:
            return None

    def add_or_update_custom_field(self, field_id, value):
        """Helper to add or update a custom field in the payload."""
        custom_fields = self.update_payload.setdefault("custom_fields", [])
        found = False
        current_value = self.get_custom_field(field_id) # Get current value from issue or payload

        if current_value == value:
            # Value is already the same, no change needed
            log.debug(f"Field {field_id} is already set to '{value}'. No update needed.")
            return

        for field in custom_fields:
            if field.get('id') == field_id:
                field['value'] = value
                found = True
                break
        if not found:
            custom_fields.append({'id': field_id, 'value': value})
        self.has_changes = True # Mark that a change has been made

    def update_timestamp(self):
        """Helper to update the upkeep timestamp in the payload."""
        today = datetime.now(timezone.utc).isoformat(timespec='seconds')
        # This update should always mark a change, as it's the upkeep timestamp
        self.add_or_update_custom_field(REDMINE_CUSTOM_FIELD_ID_UPKEEP_TIMESTAMP, today)


    def fetch_pr(self):
        prid = self.get_custom_field(REDMINE_CUSTOM_FIELD_ID_PULL_REQUEST_ID)
        if not prid:
            log.debug("[Issue #%d] No PR ID found.", self.issue.id)
            return None

        try:
            pr_id = int(prid)
        except ValueError:
            log.warning("[Issue #%d] Invalid PR ID '%s'.", self.issue.id, prid)
            return None

        if pr_id in self._pr_cache:
            return self._pr_cache[pr_id]

        endpoint = f"https://api.github.com/repos/{GITHUB_ORG}/{GITHUB_REPO}/pulls/{pr_id}"
        params = {}
        try:
            response = self.github_session.get(endpoint, auth=gitauth(), params=params)
            response.raise_for_status()
            pr_data = response.json()
            log.debug("PR #%d json:\n%s", pr_id, pr_data)
            self._pr_cache[pr_id] = pr_data
            return pr_data
        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                log.warning(f"GitHub PR #{pr_id} not found")
            else:
                log.error(f"GitHub API error for PR #{pr_id}: {e} - Response: {response.text}")
            return None
        except requests.exceptions.RequestException as e:
            log.error(f"Network or request error fetching GitHub PR #{pr_id}: {e}")
            return None

    def get_released(self, commit):
        """
        Determines the release version a commit is part of.
        """
        try:
            release = self.git_repo.git.describe('--contains', '--match', 'v*.2.*', commit)
            log.debug("[Issue #%d] release should be %s", self.issue.id, release)
            patt = r"v(\d+)\.(\d+)\.(\d+)"
            match = re.search(patt, release)
            if not match:
                log.warning("[Issue #%d] release is invalid form", self.issue.id)
                return None
            if int(match.group(2)) != 2:
                log.debug("[Issue #%d] release is not a valid release (minor version not 2)", self.issue.id)
                return None
            return release
        except git.exc.GitCommandError:
            log.debug("[Issue #%d] Commit %s not found in any matching tag.", self.issue.id, commit)
            return None
        except Exception as e:
            log.error(f"[Issue #%d] Error in get_released for commit {commit}: {e}", self.issue.id)
            return None

class RedmineUpkeep:
    def __init__(self, args):
        self.G = git.Repo(args.git)
        self.R = self._redmine_connect()
        self.limit = args.limit
        self.session = requests.Session()

        # Discover transformation methods based on prefix
        self.transform_methods = []
        for name in dir(self):
            if name.startswith('_transform_') and callable(getattr(self, name)):
                self.transform_methods.append(getattr(self, name))

        # Sort transformations for consistent order if needed, e.g., by name
        self.transform_methods.sort(key=lambda x: x.__name__)

        # Discover filter methods based on prefix
        self.filter_methods = []
        for name in dir(self):
            if name.startswith('_filter_') and callable(getattr(self, name)):
                self.filter_methods.append(getattr(self, name))

        # Sort filters for consistent order if needed, e.g., by name
        self.filter_methods.sort(key=lambda x: x.__name__)

    def _redmine_connect(self):
        log.info("connecting to %s", REDMINE_ENDPOINT)
        R = redminelib.Redmine(REDMINE_ENDPOINT, key=REDMINE_API_KEY)
        log.debug("connected")
        return R

    # Transformations:

    def _filter_merged(self, filters):
        filters[f"cf_{REDMINE_CUSTOM_FIELD_ID_PULL_REQUEST_ID}"] = '>=0'
        filters[f"cf_{REDMINE_CUSTOM_FIELD_ID_MERGE_COMMIT}"] = '!*'
        filters["status_id"] = [
            REDMINE_STATUS_ID_PENDING_BACKPORT,
            REDMINE_STATUS_ID_RESOLVED
        ]
        return filters

    def _transform_merged(self, issue_update):
        """
        Transformation: Checks if a PR associated with an issue has been merged
        and updates the merge commit and fixed_in fields in the payload.
        """
        log.info("[Issue #%d] Running _transform_merged", issue_update.issue.id)
        pr = issue_update.fetch_pr()
        if not pr:
            log.debug("[Issue #%d] No PR data found. Skipping merge check.", issue_update.issue.id)
            return

        merged = pr.get('merged')
        if not merged:
            log.debug("[Issue #%d] PR #%s not merged. Skipping merge check.", issue_update.issue.id, pr['number'])
            return

        commit = pr.get('merge_commit_sha')
        if not commit:
            log.debug("[Issue #%d] PR #%s has no merge commit SHA. Skipping merge check.", issue_update.issue.id, pr['number'])
            return

        log.info("[Issue #%d] PR #%s merged with commit %s", issue_update.issue.id, pr['number'], commit)

        # The add_or_update_custom_field method now handles checking if a change
        # is actually made and sets issue_update.has_changes accordingly.
        issue_update.add_or_update_custom_field(REDMINE_CUSTOM_FIELD_ID_MERGE_COMMIT, commit)

        try:
            ref = issue_update.git_repo.git.describe('--always', commit)
            issue_update.add_or_update_custom_field(REDMINE_CUSTOM_FIELD_ID_FIXED_IN, ref)
        except git.exc.GitCommandError as e:
            log.warning("[Issue #%d] Could not get git describe for commit %s: %s", issue_update.issue.id, commit, e)


    def _filter_released(self, filters):
        filters[f"cf_{REDMINE_CUSTOM_FIELD_ID_MERGE_COMMIT}"] = '*'
        filters[f"cf_{REDMINE_CUSTOM_FIELD_ID_RELEASED_IN}"] = '!*'
        return filters

    def _transform_released(self, issue_update):
        """
        Transformation: Checks if a merged issue has been released and updates
        the 'Released In' field in the payload.
        """
        log.info("[Issue #%d] Running _transform_released", issue_update.issue.id)
        commit = issue_update.get_custom_field(REDMINE_CUSTOM_FIELD_ID_MERGE_COMMIT)
        if not commit:
            log.debug("[Issue #%d] No merge commit set. Skipping released check.", issue_update.issue.id)
            return

        released_in = issue_update.get_custom_field(REDMINE_CUSTOM_FIELD_ID_RELEASED_IN)
        log.debug("[Issue #%d] 'Released In' currently '%s'", issue_update.issue.id, released_in)

        release = issue_update.get_released(commit)

        if release:
            issue_update.add_or_update_custom_field(REDMINE_CUSTOM_FIELD_ID_RELEASED_IN, release)
        elif released_in:
            log.error("[Issue #%d] 'Released In' would be cleared (currently: '%s')??", issue_update.issue.id, released_in)


    def _process_issue_transformations(self, issue):
        """
        Applies all discovered transformation methods to a single Redmine issue
        and sends a single update API call if changes are made.
        """
        log.info("[Issue #%d] Processing issue: '%s' %s", issue.id, issue.subject, issue.url)
        issue_update = IssueUpdate(issue, self.session, self.G)

        for transform_method in self.transform_methods:
            try:
                # Each transformation method modifies the same issue_update object
                transform_method(issue_update)
            except Exception as e:
                log.exception(f"[Issue #%d] Error applying transformation {transform_method.__name__}: {e}", issue.id)

        if issue_update.has_changes:
            issue_update.update_timestamp()
            log.info("[Issue #%d] Changes detected. Sending update to Redmine...", issue.id)
            try:
                self.R.issue.update(issue.id, **issue_update.update_payload)
                log.info(f"[Issue #%d] Successfully updated Redmine issue.", issue.id)
                return True
            except redminelib.exceptions.ValidationError as e:
                log.error(f"[Issue #%d] Redmine validation error during update: %s - Payload: %s", issue.id, e, json.dumps(issue_update.update_payload, indent=2))
                if hasattr(e, 'errors') and e.errors:
                    for error in e.errors:
                        log.error(f"  - Field: {error.get('field')}, Code: {error.get('code')}, Message: {error.get('message')}")
                raise
            except redminelib.exceptions.AuthError:
                log.exception(f"[Issue #%d] Redmine authentication failure during update.", issue.id)
                raise
            except Exception as e:
                log.exception(f"[Issue #%d] Failed to update Redmine issue: {e}", issue.id)
                return False
        else:
            log.info("[Issue #%d] No changes detected. No Redmine update sent.", issue.id)
            return False

    def filter_and_process_issues(self, issue_id=None):
        """
        Fetches issues based on filters and processes each one using all
        registered transformations.  If issue_id is provided, only that
        specific issue is processed.
        """
        if issue_id is not None:
            try:
                issue = self.R.issue.get(issue_id)
                self._process_issue_transformations(issue)
            except redminelib.exceptions.ResourceAttrError:
                log.error(f"Issue #{issue_id} not found in Redmine.")
            except Exception as e:
                log.exception(f"Error fetching or processing issue #{issue_id}: {e}")
            return

        # Process up to this many trackers.
        limit = self.limit

        now = datetime.now(timezone.utc)
        one_week_ago = now - timedelta(days=7)
        cutoff_date = one_week_ago.isoformat(timespec='seconds')

        project_id = None
        try:
            project = self.R.project.get("CephFS")
            project_id = project['id']
        except redminelib.exceptions.ResourceAttrError:
            log.error("Project 'CephFS' not found in Redmine. Cannot filter issues by project.")
            return

        # Combine filters to capture issues that might need either transformation
        # This reduces Redmine API calls for filtering
        common_filters = {
            "project_id": project_id,
            "limit": limit,
            "sort": f'cf_{REDMINE_CUSTOM_FIELD_ID_UPKEEP_TIMESTAMP}',
            "status_id": "*"
        }
        #f"cf_{REDMINE_CUSTOM_FIELD_ID_UPKEEP_TIMESTAMP}": f"<={cutoff_date}", # Not updated recently

        for filter_method in self.filter_methods:
            if limit <= 0:
                break
            try:
                common_filters['limit'] = limit
                filter_kwargs = filter_method(copy.deepcopy(common_filters))
                log.info(f"Running filter {filter_method.__name__} with criteria: {filter_kwargs}")
                try:
                    issues = self.R.issue.filter(**filter_kwargs)
                    for issue in issues:
                        limit = limit - 1
                        self._process_issue_transformations(issue)
                        if limit <= 0:
                            break
                except redminelib.exceptions.ResourceAttrError as e:
                    log.warning(f"Redmine API error with filter {filter_kwargs}: {e}")
                except Exception as e:
                    log.exception(f"Error filtering or processing issues with filter {filter_kwargs}: {e}")
            except Exception as e:
                log.exception(f"Error applying transformation {filter_method.__name__}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Ceph redmine upkeep tool")
    parser.add_argument('--debug', dest='debug', action='store_true', help='turn debugging on')
    parser.add_argument('--limit', dest='limit', action='store', type=int, default=25, help='limit processed issues')
    parser.add_argument('--git-dir', dest='git', action='store', default=".", help='git directory')
    parser.add_argument('--issue', dest='issue', action='store', help='issue to check')
    args = parser.parse_args(sys.argv[1:])

    if args.debug:
        log.setLevel(logging.DEBUG)
        git_logger = logging.getLogger('git.cmd')
        git_logger.setLevel(logging.DEBUG)
        git_logger.addHandler(logging.StreamHandler(sys.stderr))

    if not REDMINE_API_KEY:
        log.fatal("REDMINE_API_KEY not found! Please set REDMINE_API_KEY environment variable or ~/.redmine_key.")
        sys.exit(1)

    try:
        RU = RedmineUpkeep(args)
        RU.filter_and_process_issues(issue_id=args.issue)
    except Exception as e:
        log.fatal(f"An unhandled error occurred during Redmine upkeep: {e}", exc_info=True)
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
