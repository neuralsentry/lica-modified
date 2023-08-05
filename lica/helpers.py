#!/usr/bin/env python3
import re
import pickle
import pandas as pd
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, classification_report



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
    


def generate_metrics(labels, predictions):

    report = classification_report(labels,predictions,target_names=["non-bugfix", "bugfix"],)
    confusion_matrix_metric = confusion_matrix(labels,predictions)
    accuracy_metric = accuracy_score(labels, predictions)
    print(
    "\n>>> Confusion Matrix:",
    f"\nTP: {confusion_matrix_metric[1][1]}, FP: {confusion_matrix_metric[0][1]}",
    f"\nFN: {confusion_matrix_metric[1][0]}, TN: {confusion_matrix_metric[0][0]}",
    "\n\n>>> Accuracy: ",
    accuracy_metric,
    "\n\n>>>: Classification Report:\n",
    report
)