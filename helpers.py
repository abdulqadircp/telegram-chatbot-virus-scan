import requests
import time
import os
from dotenv import load_dotenv, dotenv_values
# loading variables from .env file
load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
KEY_VIRUSTOTAL = os.getenv("KEY_VIRUSTOTAL")


def check_report_status(report_link, headers):
    response = requests.get(report_link, headers=headers)
    flag = True
    counter = 0
    json_data = requests.get(report_link, headers=headers).json()
    while json_data["data"]["attributes"]["status"] == "queued":
        counter += 1
        time.sleep(5)
        json_data = requests.get(report_link, headers=headers).json()
        if counter == 10:
            flag = False
            break
    return flag, str(json_data)


def get_content_from_str_dict(message=None, substring="file_id"):
    message = str(message)
    index = message.find(substring)
    result = message[index:].split(",")[0].split(":")[
        1].replace("'", "").strip()
    return result


def get_file_report(file, api_url=None):
    files = {"file": file.content}
    headers = {"accept": "application/json",
               "X-Apikey": KEY_VIRUSTOTAL}

    response = requests.post(api_url, files=files, headers=headers)
    report_link = response.json()["data"]["links"]["self"]

    flag, data = check_report_status(report_link, headers)

    if flag:
        result = data
    else:
        result = "Failed To Generate The Scan Report [!]"
    return result


def get_url_scan_report(api_url, url):
    payload = {"url": url}
    headers = {
        "accept": "application/json",
        "x-apikey": KEY_VIRUSTOTAL,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(api_url, data=payload, headers=headers)
    report_link = response.json()["data"]["links"]["self"]
    flag = check_report_status(report_link, headers)

    flag, data = check_report_status(report_link, headers)

    if flag:
        result = data
    else:
        result = "Failed To Generate The Scan Report [!]"
    return result


def write_text_file(file_path, data):
    with open(file_path, "w") as text_file:
        text_file.write(data)
