import os
import requests
import telebot
from helpers import get_report, get_file_id_from_message






TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
KEY_VIRUSTOTAL = os.getenv("KEY_VIRUSTOTAL")
BASE_URL = "https://api.telegram.org/bot"


# You can set parse_mode by default. HTML or MARKDOWN
bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode=None)


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Howdy, how are you doing? \n 1) To Scan The File  Write file  And Upload The File \n 2) To Scan The Link  Write \link And Write The URL  ")


@bot.message_handler(content_types= ['document', 'audio','image'])
def handle_docs_audio(message):

  if message.caption:
        document = message.document
        if message.caption.startswith('/scan_file'):
            bot.reply_to(message, f"Document received for processing! File ID: {document.file_name}")
        else:
            bot.reply_to(message, "Please start your document caption with /scan_file")
  else:
      bot.reply_to(message, "Please attach a caption to your document starting with /scan_file")

  
  str_message = str(message)
  get_file_path_api_url = f'{BASE_URL}{TELEGRAM_TOKEN}/getFile?file_id={message.document.file_id}'

  file_path = requests.get(get_file_path_api_url).json()
  get_file_api_url =  f'{BASE_URL}{TELEGRAM_TOKEN}/{file_path["result"]["file_path"]}'
  file  = requests.get(get_file_api_url)

  url = "https://www.virustotal.com/api/v3/files"


  files = { "file": file.content}
  headers = {"accept": "application/json",
            "X-Apikey": KEY_VIRUSTOTAL}

  response = requests.post(url, files=files, headers=headers)
  report_link = response.json()["data"]["links"]["self"]

  report= get_report(report_link)

  file_path = f"scan_report_{document.file_name}.txt"
  with open(file_path, "w") as text_file:
    text_file.write(report)

  with open(file_path, 'rb') as file:
    bot.send_document(message.chat.id,file)
    bot.reply_to(message,f"{document.file_name} scan successfull")


bot.infinity_polling()


