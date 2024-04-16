import os
import requests
import telebot
import uuid
import time
from helpers import get_report, get_content_from_str_dict



TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
KEY_VIRUSTOTAL = os.getenv("KEY_VIRUSTOTAL")
BASE_URL = "https://api.telegram.org/bot"
bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode=None) # You can set parse_mode by default. HTML or MARKDOWN


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
  bot.reply_to(message, "Howdy, how are you doing? \n 1) To Scan The File  Write scan_file  And Upload The File \n 2) To Scan The Link  Write \link And Write The URL  ")


BASE_URL = "https://api.telegram.org/bot"
@bot.message_handler(content_types= ['document', 'photo', 'audio', 'video', 'voice'])
def handle_file(message):
  
  if message.caption:
        content_type = get_content_from_str_dict(message=message,substring="content_type")
        file_id = get_content_from_str_dict(message=message,substring="file_id")

        document = message.document
        if message.caption.startswith('/scan_file'):
            bot.reply_to(message, f"{content_type} received for scanning!")
            str_message = str(message)
            get_file_path_api_url = f'{BASE_URL}{TELEGRAM_TOKEN}/getFile?file_id={file_id}'

            file_path = requests.get(get_file_path_api_url).json()
            get_file_api_url =  f'{BASE_URL}{TELEGRAM_TOKEN}/{file_path["result"]["file_path"]}'
            file  = requests.get(get_file_api_url)

            url = "https://www.virustotal.com/api/v3/files"


            files = { "file": file.content}
            headers = {"accept": "application/json",
                      "X-Apikey": KEY_VIRUSTOTAL}

            response = requests.post(url, files=files, headers=headers)

            report_link = response.json()["data"]["links"]["self"
            time.sleep(5)
            report= get_report(report_link)

            file_path = f"scan_report_{content_type}_{str(uuid.uuid4())}.txt"
            with open(file_path, "w") as text_file:
              text_file.write(report)

            with open(file_path, 'rb') as file:
              bot.send_document(message.chat.id,file)
              bot.reply_to(message,f"{content_type} has scanned successfull")

        else:
            bot.reply_to(message, "Please start your document caption with /scan_file")
  else:
      bot.reply_to(message, "Please attach a caption to your document starting with /scan_file")



bot.infinity_polling()