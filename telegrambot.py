import os
import requests
import telebot
import uuid
import time
import mysql.connector
import pandas as pd
from helpers import get_file_report, get_content_from_str_dict, write_csv_file, get_url_scan_report, get_ip_scan_report, count_words, is_valid_ip, is_valid_url
from dotenv import load_dotenv
import mysql.connector
import matplotlib.pyplot as plt
# loading variables from .env file
load_dotenv()

SCAN_REPORTS_DIR = "scan_reports"
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
KEY_VIRUSTOTAL = os.getenv("KEY_VIRUSTOTAL")
DATABASE_HOST_ADDRESS = os.getenv("DATABASE_HOST_ADDRESS")
USERNAME = os.getenv("USERNAME")
DATABASE_PASSWORD = os.getenv("DATABASE_PASSWORD")
DATABASE_NAME = os.getenv("DATABASE_NAME")
BASE_URL = "https://api.telegram.org/bot"


conn = mysql.connector.connect(
    host=DATABASE_HOST_ADDRESS,
    user=USERNAME,
    password=DATABASE_PASSWORD,
    database=DATABASE_NAME,
)


cursor = conn.cursor()


def create_graph(chat_id, message_id, user_id):

    conn = mysql.connector.connect(
        host=DATABASE_HOST_ADDRESS,
        user=USERNAME,
        password=DATABASE_PASSWORD,
        database=DATABASE_NAME,
    )

    cursor = conn.cursor()
    # Create a cursor object
    # cursor = conn.cursor()

    # Execute SQL query to fetch request types and their counts
    print("USERID >> ", user_id)
    query = """
        SELECT RequestType, COUNT(*) AS RequestCount
        FROM Requests
        WHERE UserID = %s
        GROUP BY RequestType
    """
    data = (user_id,)
    cursor.execute(query, data)

    # Fetch the result
    results = cursor.fetchall()

    # Process the data
    request_types = []
    request_counts = []
    for row in results:
        request_types.append(row[0])
        request_counts.append(row[1])
    print("request_types >> ", request_types)
    print("request_count >> ", request_counts)
    # Create a bar chart
    plt.bar(request_types, request_counts, color='blue')
    plt.xlabel('Request Type')
    plt.ylabel('Request Count')
    plt.title('Request Types Stats')
    plt.tight_layout()  # Adjust layout to prevent clipping of labels
    # Save the graph image
    plt.savefig('request_types_distribution.png')
    bot.send_photo(chat_id=chat_id, photo=open(
        "request_types_distribution.png", 'rb'), reply_to_message_id=message_id)
    cursor.close()
    conn.close()


def insert_data_to_RequestLog(user_id, RequestType):
    conn = mysql.connector.connect(
        host=DATABASE_HOST_ADDRESS,
        user=USERNAME,
        password=DATABASE_PASSWORD,
        database=DATABASE_NAME,
    )

    cursor = conn.cursor()

    sql = """
    INSERT INTO Requests (UserID, RequestType)
    VALUES (%s, %s)
"""

    # Define the data to be inserted
    # cursor = conn.cursor()
    print("user_id in insert >>> ", user_id)
    data = (user_id, RequestType)
    cursor.execute(sql, data)
    conn.commit()

    cursor.close()
    conn.close()


bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode=None)


def send_file_to_group(file_path, message, message_id):
    with open(file_path, 'rb') as file:
        bot.send_document(message.chat.id, file,
                          reply_to_message_id=message_id)


@bot.message_handler(commands=['start', 'help'])
def send_options(message):
    options_message = f"1) To Scan The File  Type /scan_file  And Upload The File \n 2) To Scan The Link Type /scan_url   And Type The URL \n 3) To Scan The IP Type /scan_ip   And Type The IP  \n 4) To Get stats Type /request_type_stats  "
    welcome_message = f"Hello {message.from_user.first_name} How can I protect you? \n"

    keyboard = telebot.types.InlineKeyboardMarkup()

    keyboard.row(
        telebot.types.InlineKeyboardButton(
            'Scan File', callback_data='scan_file'),
        telebot.types.InlineKeyboardButton(
            'Scan URL', callback_data='scan_url'),
        telebot.types.InlineKeyboardButton('Scan IP', callback_data='scan_ip'),

    )
    keyboard.row(telebot.types.InlineKeyboardButton(
        'Get Request Type Stats', callback_data='get_stats'))
    bot.send_message(message.chat.id, welcome_message +
                     options_message, reply_markup=keyboard)


@bot.callback_query_handler(func=lambda call: True)
def iq_callback(query):
    data = query.data
    if data == "scan_file":
        file_scan_request(query.message)
    if data == "scan_url":
        url_scan_request(query.message)
    if data == "scan_ip":
        ip_scan_request(query.message)
    if data == "get_stats":
        print("user_id = query.from_user.id >>", query.from_user.id)
        get_request_type_stats(query.message, query.from_user.id)


def invalid_input_message(message):
    bot.send_message(
        message.chat.id, "You Input The Invalid Value \nTo See Options Use /help ")


@bot.message_handler(commands=['scan_file'], content_types=['text'])
def file_scan_request(message):
    bot.reply_to(message, f"Add File To Scan.")
    bot.register_next_step_handler(message, handle_files)

# @bot.message_handler(commands=['scan_file'],content_types= ['text','document', 'photo', 'audio', 'video', 'voice'])


def handle_files(message):

    if message.content_type == 'text':
        bot.reply_to(
            message, f"Please Attach A File [!]\n You Passed a {message.content_type}")
        invalid_input_message(message=message)

    else:  # message.caption.startswith('/scan_file'):
        # get_content_from_str_dict(message=message,substring="content_type")
        content_type = message.content_type
        file_id = get_content_from_str_dict(
            message=message, substring="file_id")
        insert_data_to_RequestLog(
            user_id=message.from_user.id, RequestType="File")
        bot.reply_to(message, f"{content_type} received for scanning!")
        str_message = str(message)
        get_file_path_api_url = f'{BASE_URL}{TELEGRAM_TOKEN}/getFile?file_id={file_id}'

        file_path = requests.get(get_file_path_api_url).json()
        get_file_api_url = f'{BASE_URL}{TELEGRAM_TOKEN}/{file_path["result"]["file_path"]}'
        file = requests.get(get_file_api_url)

        api_url = "https://www.virustotal.com/api/v3/files"
        time.sleep(5)
        report = get_file_report(file=file, api_url=api_url)
        file_name = f"scan_report_{content_type}_{str(uuid.uuid4())}.csv"
        file_path = os.path.join(SCAN_REPORTS_DIR, file_name)
        write_csv_file(file_path=file_path, data=report)
        send_file_to_group(file_path=file_path, message=message,
                           message_id=message.message_id)
        bot.reply_to(message, f"{content_type} has scanned successfully")


@bot.message_handler(commands=['scan_ip'], content_types=['text'])
def ip_scan_request(message):
    bot.reply_to(message, f"Write IP Address To Scan.")
    bot.register_next_step_handler(message, handle_ip)


def handle_ip(message):
    if message.content_type != 'text':
        bot.reply_to(
            message, f"Please Pass An IP Address [!]\n You Passed a {message.content_type}")
        send_options(message=message)
    is_ip, ip_tpe = is_valid_ip(message.text)
    if is_ip:
        ip = message.text  # message.text.strip().split("scan_ip :")[1].strip()
        insert_data_to_RequestLog(
            user_id=message.from_user.id, RequestType="IP")
        bot.reply_to(message, f"IP {ip} received for scanning!")
        api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        report = get_ip_scan_report(api_url=api_url)
        file_name = f"scan_report_ip_{str(uuid.uuid4())}.csv"
        file_path = os.path.join(SCAN_REPORTS_DIR, file_name)
        write_csv_file(file_path=file_path, data=report)
        send_file_to_group(file_path=file_path, message=message,
                           message_id=message.message_id)
        df = pd.read_csv(file_path)
        malicious_count = count_words(
            df, "result", ["malicious", "suspicious", "malware"])
        total_vendor = df.shape[0]
        bot.reply_to(
            message, f"{malicious_count}/{total_vendor} security vendor flagged this IP , \nIP has scanned successfully")
        # bot.send_message(chat_id="6454899492", text="namaste2!!")
    else:
        bot.reply_to(message, f"Please Enter Valid IP")
        invalid_input_message(message=message)


@bot.message_handler(commands=['scan_url'], content_types=['text'])
def url_scan_request(message):
    bot.reply_to(message, f"Write URL To Scan.")
    bot.register_next_step_handler(message, handle_url)


def handle_url(message):
    if is_valid_url(message.text):
        url = message.text  # message.text.strip().split("scan_url :")[1]
        insert_data_to_RequestLog(
            user_id=message.from_user.id, RequestType="URL")
        bot.reply_to(message, f"URL {url} received for scanning!")
        api_url = "https://www.virustotal.com/api/v3/urls"
        report = get_url_scan_report(api_url=api_url, url=url)
        file_name = f"scan_report_url_{str(uuid.uuid4())}.csv"
        file_path = os.path.join(SCAN_REPORTS_DIR, file_name)
        write_csv_file(file_path=file_path, data=report)
        send_file_to_group(file_path=file_path, message=message,
                           message_id=message.message_id)
        df = pd.read_csv(file_path)
        malicious_count = count_words(
            df, "result", ["malicious", "malware", "suspicious"])
        total_vendor = df.shape[0]
        bot.reply_to(
            message, f"{malicious_count}/{total_vendor} security vendor flagged this URL,\nURL has scanned successfully")
    else:
        bot.reply_to(message, f"Please Enter Valid URL")
        invalid_input_message(message=message)


@bot.message_handler(commands=['request_type_stats'])
def get_request_type_stats(message, user_id=None):
    if not (user_id):
        user_id = message.from_user.id
    bot.send_message(message.chat.id, f"Request for the stats has recieved.")
    create_graph(message.chat.id, message.message_id,
                 user_id=user_id)


bot.infinity_polling()
