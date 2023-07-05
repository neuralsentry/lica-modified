#!/usr/bin/env python3
import subprocess
import pandas as pd
from datetime import datetime, timedelta

from config import *
from helpers import *



def filter_commits(commits):
    """ wip """
    res = []
    threshold = 0.1
    total = commits.shape[0]
    global STATS

    print(f"|---- Filtering {total} commits\n|---- ", end='')
    for index, commit in commits.iterrows():
        STATS["commits"] += 1

        if not filter_title(CONFIG, get_commit_title(commit)):
            continue
        if any(hit in get_commit_title(commit) for hit in ["Merge", "Revert"]):
            continue
        STATS["fixes"] += 1

        hits = filter_commit(CONFIG, commit)
        if not hits:
            continue
        STATS["filtered"] += 1

        reporter = get_commit_reporter(commit['commit_msg'])
        CVEs = get_commit_cves(commit['commit_msg']) # enough to not check title?

        if not filter_reporter(CONFIG, reporter):
            continue

        res.append({
            "sha": commit.sha,
            "module": get_commit_module(commit),
            "title": get_commit_title(commit),
            "message": commit['commit_msg'],
            "reporter": reporter,
            "cves": ",".join(list(dict.fromkeys(CVEs))), # remove duplicates
            "hits": list(dict.fromkeys(hits)), # remove duplicates
            "coverage": "N/A",
            "remote_url": commit['remote_url'],
            "date": commit['date'],
            "labels": 1
        })

        if (STATS["commits"] / total) > threshold:
            print(f"{threshold*100:.0f}%...", end='')
            threshold += 0.1

    print('')
    return res

def get_coverage(fcommits):
    """ wip """
    for commit in fcommits:
        coverage = []
        skip = False

        for change in commit["files"]:
            changes = parse_patch(change.patch)
            for kvers in CONFIG["coverage_list"]:
                if not file_has_changes(kvers, change.filename, changes):
                    skip = True
                    break
                coverage.append(kvers.split('/')[-1]) # remove path, just folder name for stats
            if skip:
                break

        if coverage and not skip:
            commit["coverage"] = ", ".join(list(dict.fromkeys(coverage)))


def parse_stats(fcommits):
    """ wip """
    global STATS

    for cat in CONFIG["message_filter"]:
        STATS["hits"][cat] = 0

    for com in fcommits:
        module = com["module"].split('/')[0].split(',')[0]

        if module not in STATS["modules"]:
            STATS["modules"][module] = 1
        else:
            STATS["modules"][module] += 1

        if com["reporter"]:
            STATS["reported"] += 1

        if com["cves"]:
            STATS["cves"] += 1

        parse_filter_hits(CONFIG, STATS, com["hits"])

    STATS["modules"] = dict(sorted(STATS["modules"].items(), key=lambda item: item[1], reverse=True))
    STATS["hits"] = dict(sorted(STATS["hits"].items(), key=lambda item: item[1], reverse=True))



def print_commits(fcommits):
    """ wip """
    print(f"\n{'Commit':.<12} | {'Module':.<18} | {'Hits':.<60} | {'CVE':.<16} | {'Reporter':.<50} | {'Coverage':.<15}")
    print("-"*186)

    for com in fcommits:
        sha = com["sha"][:12]
        hits = ",".join(com["hits"])[:57]
        print(f"{sha:<12} | {com['module']:<18} | {hits:.<60} | {com['cves']:<16} | {com['reporter']:<50} | {com['coverage']:<15}")

    print("-"*186)


def print_stats():
    """ wip """
    global STATS

    print("Now For The Stats...")
    print("-"*186)

    print(f"[+] {STATS['filtered']} commits where matched from {STATS['fixes']} fixes, over {STATS['commits']} commits.")
    print(f"[+] {STATS['reported']} / {STATS['filtered']} listed a reporter.")
    print(f"[+] {STATS['cves']} / {STATS['filtered']} mentioned a CVE.")

    print(f"[+] Breakdown by category:")
    for cat in STATS["hits"]:
        print(f"|---- {cat}: {STATS['hits'][cat]}")

    print(f"[+] Breakdown by module:")
    for module in STATS["modules"]:
        print(f"|---- {module}: {STATS['modules'][module]}")


def main():

    print_banner()

    print("[+] Fetching commits from csv...")

    df = pd.read_csv('lica/linux_cves.csv')
    print("[+] Filtering commits based on config.py, this may involve some more API calls...")
    fcommits = filter_commits(df)

    parse_stats(fcommits)

    print_commits(fcommits)
    print_stats()
    # Generate prediction dataset
    pred_ds = pred_dataset(df,fcommits)
    y_ds = pd.read_csv('lica/linux_cves.csv')
    generate_metrics(y_ds, pred_ds)

if __name__ == "__main__":
    main()