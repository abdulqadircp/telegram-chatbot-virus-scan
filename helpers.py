def get_content_from_str_dict(message=None,substring="file_id"):
  message = str(message)
  index = message.find(substring)
  result = message[index:].split(",")[0].split(":")[1].replace("'","").strip()
  return result


def get_report(report_link=None):
  headers = {"accept": "application/json",
            "X-Apikey": KEY_VIRUSTOTAL}

  
  response = requests.get(report_link, headers=headers)
  flag = True
  counter = 0
  json_data = requests.get(report_link, headers=headers).json()
  while json_data["data"]["attributes"]["status"] == "queued":
    counter+=1
    time.sleep(5)
    json_data = requests.get(report_link, headers=headers).json()
    if counter == 10:
      flag = False
      break

  if flag:
    result = response.text
  else:
    result = "Failed To Generate The Scan Report [!]"  
  return result