import os
import requests
import telebot
from helpers import get_report, get_file_id_from_message



def get_report(report_link=None):
  headers = {"accept": "application/json",
            "X-Apikey": KEY_VIRUSTOTAL}

  id = 'ODFiMTg0NWQ0NmJjZWZmOWM5ODY1NWM3YzVlZTlkMjU6MTcxMjQxOTEyOA=='
  response = requests.get(report_link, headers=headers)

  print("response >>> ",response.text)
  return response.text



TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
KEY_VIRUSTOTAL = os.getenv("KEY_VIRUSTOTAL")

# You can set parse_mode by default. HTML or MARKDOWN
bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode=None)


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Howdy, how are you doing?")


@bot.message_handler(content_types=['document', 'audio'])
def handle_docs_audio(message):
    str_message = str(message)
    file_id = get_file_id_from_message(message=str_message)

    get_file_path_api_url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/getFile?file_id={file_id}'

    file_path = requests.get(get_file_path_api_url).json()

    get_file_api_url = f'https://api.telegram.org/file/bot{TELEGRAM_TOKEN}/{file_path["result"]["file_path"]}'
    file = requests.get(get_file_api_url)

    url = "https://www.virustotal.com/api/v3/files"

    files = {"file": file.content}
    headers = {"accept": "application/json",
               "X-Apikey": KEY_VIRUSTOTAL}

    response = requests.post(url, files=files, headers=headers)
    report_link = response.json()["data"]["links"]["self"]

    report = get_report(report_link)

    print("########### Report ############ ", report)
    bot.reply_to(report)


bot.infinity_polling()


