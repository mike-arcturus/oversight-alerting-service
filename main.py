import smtplib
import json
import copy
import time
from email.mime.text import MIMEText

"""
How to update:
add client code to CLIENTS, add client name "as you want to appear on email" to CLIENT_NAMES, add alertees, an empty 
list for "alrt_for" indicates to alert for all clients. otherwise alert only for the ones in the list (use the 4 letter 
codes as they appear in the CLIENTS lsit)

how to run:
python3 main.py
"""

#  Add IDs here you don't want alerts out for
IGNORE_DICTIONARY = {
    "client_name": ["nessus-123", "nessus_234"],
}

# 4 letter client codes here #  todo-pull this from API this is not scalable
CLIENTS = ["NIUK", "GARS", "LOVE", "FINI", "RICH"]

#
CLIENT_NAMES = {
    "NIUK": "Newbury Investments",
    "GARS": "Gardiner Bros",
    "LOVE": "Love Energy",
    "RICH": "Richer Sounds",
    "FINI": "Wifinity"
}

ALERTEES = [
{"address": "alex.mayne@arcturussecurity.com",
     "alert_for": []},
{"address": "michal.nerek@arcturussecurity.com",
     "alert_for": []},
{"address": "tyler.sullivan@arcturussecurity.com",
     "alert_for": []},
{"address": "ria.watson@arcturussecurity.com",
     "alert_for": []},
{"address": "luke.rummey@arcturussecurity.com",
     "alert_for": []},
]


def send_mail(sender, recievers, message, subject):
    for reciever in recievers:
        smpt_client = smtplib.SMTP("arcturussecurity-com.mail.protection.outlook.com")
        smpt_client.set_debuglevel(1)
        smpt_client.starttls()
        smpt_client.ehlo()
        msg = MIMEText(message)
        recipients = reciever
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipients
        smpt_client.send_message(msg)
        time.sleep(5)


def get_results():
    latest_scans = {}
    for client in CLIENTS:
        with open(f"/home/blobcat/test_data/{client.lower()}_dataset.json") as f:
            scans = json.load(f)
            latest_scan = scans["SCANS"][-1]
            latest_scans[client] = latest_scan
    return latest_scans


def get_ignores():
    try:
        with open("vuln_history.json", "r") as f:
            vuln_history = json.load(f)
    except FileNotFoundError:
        print("no vuln history file found, assuming first time run")
        vuln_history = {}
    return vuln_history


def update_ignores(ignore):
    with open("vuln_history.json", "w") as f:
        json.dump(ignore, f)


def check_for_crits(scans):
    crits = []
    for client in CLIENTS:
        for vuln in scans[client]["top_vulns"]:
            if vuln['cvss_score'] > 9.0:
                vuln["client"] = client
                vuln["date"] = scans[client]["date"]
                crits.append(copy.deepcopy(vuln))
    return crits


def compare_crits(vulns):
    ignore = get_ignores()
    new_vulns = []
    for vuln in vulns:
        id = vuln["client"]+vuln["asset"]+vuln["id"]
        if id not in ignore.keys(): # A: never seen before, B: seen before but more than a month ago, C: seen less than a month ago (no code needed)
            new_vulns.append(vuln)
        elif time.time() - ignore[id] > 2628000:  # seconds in a month (time now - time last seen > one month)
            new_vulns.append(vuln)
        ignore[id] = vuln['date']
    update_ignores(ignore)
    return new_vulns


def alert(vulns):
    sender = "oversight@arcturussecurity.com"
    for vuln in vulns:
        #  prep message
        subject = f'Subject: Oversight alert for {CLIENT_NAMES[vuln["client"]]} - {vuln["risk_level"]}'
        message = f'The Oversight Scanner has discovered a new {vuln["risk_level"]} - risk vulnerability. It has been found on {vuln["asset"]}. Please see the Oversight portal for more information.'
        #  check whom to send it to
        recievers = []
        for alertee in ALERTEES:
            if alertee["alert_for"]:
                if vuln['client'] not in alertee['alert_for']:
                    continue
            recievers.append(alertee['address'])
        send_mail(sender, recievers, message, subject)


def main():
    print("obtaining today's results")
    today_scans = get_results()
    print("checking for new crits")
    today_crits = check_for_crits(today_scans)
    print(f"{len(today_crits)} crits today")
    print("checking if any are new")
    new_crits = compare_crits(today_crits)
    print(f"{len(new_crits)} alertable vulns found, sending alerts!")
    alert(new_crits)
    print("All done uwu")


if __name__ == '__main__':
    main()
    pass
