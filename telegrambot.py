import os
import requests
import telebot
import uuid
import time
from helpers import get_file_report, get_content_from_str_dict, write_text_file, get_url_scan_report
from dotenv import load_dotenv
# loading variables from .env file
load_dotenv()

SCAN_REPORTS_DIR = "scan_reports"
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
KEY_VIRUSTOTAL = os.getenv("KEY_VIRUSTOTAL")
BASE_URL = "https://api.telegram.org/bot"
# You can set parse_mode by default. HTML or MARKDOWN
bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode=None)


def send_file_to_group(file_path, message):
    with open(file_path, 'rb') as file:
        bot.send_document(message.chat.id, file)


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Howdy, how are you doing? \n 1) To Scan The File  Write scan_file  And Upload The File \n 2) To Scan The Link  Write scan_url :  And Write The URL  ")


@bot.message_handler(content_types=['document', 'photo', 'audio', 'video', 'voice'])
def handle_files(message):
    if message.caption:

        if message.caption.startswith('/scan_file'):
            content_type = get_content_from_str_dict(
                message=message, substring="content_type")
            file_id = get_content_from_str_dict(
                message=message, substring="file_id")
            bot.reply_to(message, f"{content_type} received for scanning!")
            str_message = str(message)
            get_file_path_api_url = f'{BASE_URL}{TELEGRAM_TOKEN}/getFile?file_id={file_id}'

            file_path = requests.get(get_file_path_api_url).json()
            get_file_api_url = f'{BASE_URL}{TELEGRAM_TOKEN}/{file_path["result"]["file_path"]}'
            file = requests.get(get_file_api_url)

            api_url = "https://www.virustotal.com/api/v3/files"
            time.sleep(5)
            report = get_file_report(file=file, api_url=api_url)
            file_name = f"scan_report_{content_type}_{str(uuid.uuid4())}.txt"
            file_path = os.path.join(SCAN_REPORTS_DIR, file_name)
            write_text_file(file_path=file_path, data=report)
            send_file_to_group(file_path=file_path, message=message)
            bot.reply_to(message, f"{content_type} has scanned successfull")

        else:

            bot.reply_to(
                message, "Please start your document caption with /scan_file")
    else:
        bot.reply_to(
            message, "Please attach a caption to your document starting with /scan_file")


@bot.message_handler(content_types=['text'])
def handle_files(message):
    if "scan_url :" in message.text:

        url = message.text.strip().split("scan_url :")[1]
        bot.reply_to(message, f"URL {url} received for scanning!")
        api_url = "https://www.virustotal.com/api/v3/urls"
        report = get_url_scan_report(api_url=api_url, url=url)
        file_name = f"scan_report_url_{str(uuid.uuid4())}.txt"
        file_path = os.path.join(SCAN_REPORTS_DIR, file_name)
        write_text_file(file_path=file_path, data=report)
        send_file_to_group(file_path=file_path, message=message)
        bot.reply_to(message, f"URL has scanned successfull")


bot.infinity_polling()
