def get_file_id_from_message(message=None):
  substring = "file_id"
  index = message.find(substring)
  result = message[index:].split(",")[0].split(":")[1].replace("'","").strip()
  return result



def get_report(report_link=None):
  headers = {"accept": "application/json",
            "X-Apikey": KEY_VIRUSTOTAL}

  id = 'ODFiMTg0NWQ0NmJjZWZmOWM5ODY1NWM3YzVlZTlkMjU6MTcxMjQxOTEyOA=='
  response = requests.get(report_link, headers=headers)

  print("response >>> ",response.text)
  return response.text