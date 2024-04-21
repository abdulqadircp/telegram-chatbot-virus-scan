import requests
import time
import os
import pandas as pd
import json
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
    print("json_data >> ", json_data)
    while json_data["data"]["attributes"]["status"] == "queued":
        counter += 1
        time.sleep(5)
        json_data = requests.get(report_link, headers=headers).json()

        if counter == 100:
            flag = False
            break
    return flag, json_data


def get_content_from_str_dict(message=None, substring="file_id"):
    message = str(message)
    index = message.find(substring)
    result = message[index:].split(",")[0].split(":")[
        1].replace("'", "").strip()
    return result


def get_relevant_data_from_api_response(data, result="results"):
    # get_relevant_data_from_api_response for File and URL api response
    print("data >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>######################################################>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n", type(data), " ", data)
    merged_dict = {}
    for key in data["data"]["attributes"][result].keys():
        anti_virus = data["data"]["attributes"][result][key]
        # dicts = [dict1, dict2, dict3]

        # Merge dictionaries
        for key, value in anti_virus.items():
            if key not in merged_dict:
                merged_dict[key] = [value]
            else:
                merged_dict[key].append(value)
    return merged_dict


def get_file_report(file, api_url=None):
    files = {"file": file.content}
    headers = {"accept": "application/json",
               "X-Apikey": KEY_VIRUSTOTAL}

    response = requests.post(api_url, files=files, headers=headers)
    report_link = response.json()["data"]["links"]["self"]

    flag, data = check_report_status(report_link, headers)

    if flag:

        result = get_relevant_data_from_api_response(data)

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
        result = get_relevant_data_from_api_response(data)
    else:
        result = "Failed To Generate The Scan Report [!]"
    return result


def get_ip_scan_report(api_url):

    headers = {
        "accept": "application/json",
        "x-apikey": KEY_VIRUSTOTAL,
    }

    response = requests.get(api_url, headers=headers)
    result = response.json()["data"]["attributes"]
    # print("get_relevant_data_from_api_response >>> ",response.json()["data"]["attributes"])
    result = get_relevant_data_from_api_response(
        response.json(), result="last_analysis_results")
    return result


def write_csv_file(file_path, data):
    # data =json.loads(data)

    df = pd.DataFrame(data)
    df.to_csv(file_path, index=False)
    # with open(file_path, "w") as text_file:
    #     text_file.write(data)
