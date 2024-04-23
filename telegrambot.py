import os
import requests
import telebot
import uuid
import time
import mysql.connector
from helpers import get_file_report, get_content_from_str_dict, write_csv_file, get_url_scan_report, get_ip_scan_report
from dotenv import load_dotenv

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
    import mysql.connector
    import matplotlib.pyplot as plt

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

    # Create a bar chart
    plt.bar(request_types, request_counts, color='blue')
    plt.xlabel('Request Type')
    plt.ylabel('Request Count')
    plt.title('Request Types Distribution')
    plt.tight_layout()  # Adjust layout to prevent clipping of labels
    # Save the graph image
    plt.savefig('request_types_distribution.png')
    bot.send_photo(chat_id=chat_id, photo=open(
        "request_types_distribution.png", 'rb'), reply_to_message_id=message_id)
    # cursor.close()


def insert_data_to_RequestLog(user_id, RequestType, conn=conn):
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

    # cursor.close()


# def read_data():
#     query = """
#     SELECT *
#     FROM Requestlog
# """
#     cursor = conn.cursor()
#     cursor.execute(query)

#     # Fetch all the results
#     results = cursor.fetchall()

#     # Print the results
#     for row in results:
#         print(row)

#     # Close the cursor and connection
#     #cursor.close()

# read_data()
bot = telebot.TeleBot(TELEGRAM_TOKEN, parse_mode=None)


def send_file_to_group(file_path, message, message_id):
    with open(file_path, 'rb') as file:
        bot.send_document(message.chat.id, file,
                          reply_to_message_id=message_id)


@bot.message_handler(commands=['start', 'help'])
def send_welcome(message):
    bot.reply_to(message, "Howdy, how are you doing? \n 1) To Scan The File  Type scan_file  And Upload The File \n 2) To Scan The Link Type scan_url :  And Type The URL \n 3) To Scan The IP Type scan_ip :  And Type The IP  \n 4) To Get stats Type request_type_stats : ")


@bot.message_handler(content_types=['document', 'photo', 'audio', 'video', 'voice'])
def handle_files(message):
    if message.caption:
        if message.caption.startswith('/scan_file'):
            content_type = get_content_from_str_dict(
                message=message, substring="content_type")
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
            send_file_to_group(file_path=file_path,
                               message=message, message_id=message.message_id)
            bot.reply_to(message, f"{content_type} has scanned successfull")
        else:
            bot.reply_to(
                message, "Please start your document caption with /scan_file")
    else:
        bot.reply_to(
            message, "Please attach a caption to your document starting with /scan_file")


@bot.message_handler(content_types=['text'])
def handle_urls_IP(message):
    if "scan_url :" in message.text:
        url = message.text.strip().split("scan_url :")[1]
        # print("message.from_user.id >> ",message.from_user.id)
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
        bot.reply_to(message, f"URL has scanned successfull")
        # bot.send_message(chat_id="6454899492", text="namaste!!")
    elif "scan_ip :" in message.text:
        ip = message.text.strip().split("scan_ip :")[1].strip()
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
        bot.reply_to(message, f"IP has scanned successfully")
        # bot.send_message(chat_id="6454899492", text="namaste2!!")
    elif "request_type_stats :" in message.text:
        bot.reply_to(message, f"request for the stats has recieved.")
        create_graph(message.chat.id, message.message_id,
                     user_id=message.from_user.id)


if __name__ == '__main__':
    bot.infinity_polling()
