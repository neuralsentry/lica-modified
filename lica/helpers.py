#!/usr/bin/env python3
import re
import pickle
import pandas as pd
from sklearn import metrics

def print_banner():
    """ does what it says on the tin """
    print("""
          .____    .__
          |    |   |__| ____ _____
          |    |   |  |/ ___\\\\__  \\
          |    |___|  \\  \\___ / __ \\_
          |_______ \\__|\___  >____  /
                  \\/       \\/     \\/

                   - some kind of tool to analyse Linux kernel commits.
    """)



def sha_from_release_tag(repo, release):
    """ wip """
    tags = repo.get_tags()
    for tag in tags:
        if tag.name == release:
            return tag.commit.sha
    return None


def filter_to_regex_string(filter_obj):
    """ wip """
    if isinstance(filter_obj, str):
        return filter_obj

    strs = []
    for entry in filter_obj:
        if isinstance(filter_obj, list):
            strs.append(entry)
        elif isinstance(filter_obj, dict):
            strs += filter_obj[entry]

    return "(" + "|".join(strs) + ")"


def get_commit_title(commit):
    """ wip """
    # msg = commit.commit.message
    msg = str(commit['commit_msg'])
    return msg.split('\n', 1)[0].strip()


def get_commit_module(commit):
    """ wip """
    title = get_commit_title(commit)
    return title.split(':')[0].lstrip()


def get_commit_reporter(msg):
    """ wip """
    if "Reported-by:" not in msg:
        return ""
    for line in msg.splitlines():
        if "Reported-by:" not in line:
            continue
        return line.replace("Reported-by:", "").strip()
    return ""


def get_commit_cves(msg):
    """ wip """
    if "CVE" not in msg:
        return []
    return re.findall(r"cve-\d{4}-\d{4,7}", msg.lower())


def filter_title(config, title):
    """ wip """
    title_regex = filter_to_regex_string(config["title_filter"])
    pattern = re.compile(title_regex)
    return pattern.findall(title) # returns True on match

def filter_commit(config, commit):
    """ wip """
    if config["message_ignore"]:
        msg_regex = filter_to_regex_string(config["message_ignore"])
        pattern = re.compile(msg_regex)
        if pattern.findall(commit['commit_msg']):
            return
    msg_regex = filter_to_regex_string(config["message_filter"])
    pattern = re.compile(msg_regex)
    title = get_commit_title(commit)

    title_hits = pattern.findall(title)
    message_hits = pattern.findall(commit['commit_msg'])

    return title_hits + message_hits  # returns True on match


def filter_reporter(config, reporter):
    """ wip """
    if not config["reporter_filter"]:
        return True # no filter
    reporter_regex = filter_to_regex_string(config["message_filter"])
    pattern = re.compile(reporter_regex)
    return pattern.findall(reporter)


def parse_filter_hits(config, stats, hits):
    """ wip """
    msg_filter = config["message_filter"]

    try:
        for hit in hits:
            cat = [k for k, v in msg_filter.items() if hit in v][0]
            stats["hits"][cat] += 1
    except:
        return # if filters were regex, the above bit doesn't work, should fix


def parse_patch(patch):
    """ wip """
    changes = { "added": [], "removed": [] }

    for line in patch.splitlines():
        if line[0] == "+":
            changes["added"].append(line[1:].strip())
        elif line[0] == "-":
            changes["removed"].append(line[1:].strip())

    return changes


def file_has_changes(kvers, file_name, changes):
    """ wip """
    file_path = f"{kvers}/{file_name}"
    try:
        with open(file_path) as kfile:
            contents = kfile.read()
            if changes["removed"] and all(x in contents for x in changes["removed"]):
                return False # all of the removed lines are still present in this kvers' file
            if changes["added"] and not all(x in contents for x in changes["added"]):
                return False # the new added lines aren't in this kvers' file
        return True # removed aren't present + added are present
    except:
        return False # file not found, default to false
    


def pred_dataset(test_ds,fcommits):
    # Convert all labels to non-bug before merging
    test_ds.loc[test_ds.labels == 1, 'labels'] = 0
    test_ds = test_ds.sort_values(by='commit_msg', ascending=True)
    commit_msg, sha, remote_url, date, labels = [], [], [], [], []
    for commits in fcommits:
        commit_msg.append(commits['message'])
        sha.append(commits['sha'])
        remote_url.append(commits['remote_url'])
        date.append(commits['date'])
        labels.append(commits['labels'])

    data = {
        "commit_msg": commit_msg,
        "sha": sha,
        "remote_url": remote_url,
        "date": date,
        "labels": labels
    }

    df = pd.DataFrame(data, columns=["commit_msg", "sha", "remote_url", "date", "labels"])
    pred_ds = pd.concat([test_ds, df]).drop_duplicates(subset=['sha'], keep='last')
    pred_ds = pred_ds.sort_values(by='commit_msg', ascending=True)
    return pred_ds


def generate_metrics(test_ds, pred_ds):
    # print(test_ds.head(20))
    y_test = test_ds['labels']
    y_pred = pred_ds['labels']

    print('\nMETRICS')
    print(f'Precision: {metrics.precision_score(y_test, y_pred)}')
    print(f'Recall: {metrics.recall_score(y_test, y_pred)}')
    print(f'F1: {metrics.f1_score(y_test, y_pred)}')