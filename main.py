import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QHBoxLayout, QVBoxLayout, QPlainTextEdit, QLabel, QSpacerItem, QListWidget, QListWidgetItem
from PyQt5.QtCore import pyqtSignal
import base64
import threading
import time
import os
from google.oauth2 import service_account
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import undetected_chromedriver as uc
from webdriver_manager.chrome import ChromeDriverManager
import uuid
import json
import subprocess
import requests
from http.server import HTTPServer, SimpleHTTPRequestHandler
from ssl import PROTOCOL_TLS_SERVER, SSLContext

# Constants
CHECK_INTERVAL = 60
FIXED_MAIL_PWD = 'Pennedsms20!'
HTTP_PORT = 3000
LOG_FILE = 'corrlinks_registration.log'
API_BASEURL = 'https://pennedsms.com'
CATCHALL_MAIL = 'catchall@withfath.com'
MAX_SENDWELCOME_RETRY = 10
WELCOME_TEXT = """
**Welcome to PennedSMS!**


We’re thrilled to have you on board! PennedSMS is designed to simplify communication by allowing you to manage your contacts efficiently and stay connected. Please follow the instructions below to set up your contacts and start using our service smoothly.

### **Setting Up Your Contact List**

To manage your contacts, you will need to use the keyword "JACK" in the subject line of your messages. Below is a guide on how to add or delete contacts:

**1. Adding a Contact:**

- **Step 1:** In the **subject line**, type **JACK**.
- **Step 2:** In the **body of the message**, type the keyword associated with the contact, followed by the contact’s phone number. 
- **Step 3:** Add a **+** sign to include this contact in your list.

**Example to Add a Contact:**
```
Subject: JACK
Body: JOHN 12345678901+
```

**2. Deleting a Contact:**

- **Step 1:** In the **subject line**, type **JACK**.
- **Step 2:** In the **body of the message**, type the keyword associated with the contact, followed by the contact’s phone number. 
- **Step 3:** Add a **-** sign to remove this contact from your list.

**Example to Delete a Contact:**
```
Subject: JACK
Body: JOHN 12345678901-
```

### **Important Notes:**

- **Phone Numbers:** Ensure that all phone numbers include a “1” at the beginning (e.g., 12345678901).
- **Keywords:** The keyword should be unique to each contact to avoid confusion. For example, you can use the first name of the contact.
- **Accuracy:** Double-check the phone number and keyword before sending the message to ensure that the correct contact is added or deleted.


Thank you for choosing PennedSMS, and we look forward to making your communication seamless and efficient!

Best regards,  
The PennedSMS Team
www.pennedsms.com
"""

# HTTP request handler
class MyRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.mainWindow = kwargs.pop('mainwindow', None)
        super().__init__(*args, **kwargs)

    def do_POST(self):
        if self.path == '/register':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            try:
                data = json.loads(post_data)
                self.mainWindow.create_user_signal.emit(data)
            except Exception as error:
                pass

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Ok")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Doesn't exist")
        return

    def log_message(self, format, *args):
        pass

class MailItemWidget(QWidget):
    def __init__ (self, parent = None):
        super().__init__(parent)

        self.mail_label = QLabel()
        self.info_label = QLabel()

        layout = QVBoxLayout()
        layout.addWidget(self.mail_label)
        layout.addWidget(self.info_label)
        self.setLayout(layout)

    def setMail(self, value):
        self.mail_label.setText(value)

    def setInfo(self, fn, ln, pwd):
        self.info_label.setText(f'First name: {fn}, Last name: {ln}, Pwd: {pwd}')

    def getMail(self):
        return self.mail_label.text()

class MainWindow(QWidget):
    add_log_signal = pyqtSignal(str)
    add_user_signal = pyqtSignal(dict)
    user_registered_signal = pyqtSignal(str)
    create_user_signal = pyqtSignal(dict)

    def __init__(self):
        super().__init__()

        # Set up the window
        self.initUI()

        # init
        self.user_queue = [
            {
                'email': CATCHALL_MAIL
            }
        ]
        self.log_cnt = 0
        self.log_file = open(LOG_FILE, 'a')
        self.api_token = ''

        self.add_log_signal.connect(self.addLog)
        self.add_user_signal.connect(self.addUserToList)
        self.create_user_signal.connect(self.createGmail)
        self.user_registered_signal.connect(self.registerUser)
        self.initServiceAccount()
        threading.Thread(target=self.initHttpServer).start()

    def initUI(self):
        self.setWindowTitle('Corrlinks Registration Bot')

        # Set up layout
        layout = QVBoxLayout()

        layout1 = QHBoxLayout()
        layout1_1 = QVBoxLayout()
        layout1_2 = QVBoxLayout()

        layout1_1.addWidget(QLabel("Queue for registration"))
        self.list_mails = QListWidget()
        layout1_1.addWidget(self.list_mails)

        layout1_2.addWidget(QLabel("Recent logs"))
        self.log_widget = QPlainTextEdit()
        self.log_widget.setReadOnly(True)
        layout1_2.addWidget(self.log_widget)

        layout1.addLayout(layout1_1)
        layout1.addLayout(layout1_2)
        layout.addLayout(layout1)

        layout.addSpacerItem(QSpacerItem(1, 10))

        self.btn_logs = QPushButton("Logs")
        self.btn_logs.clicked.connect(self.openLogFile)
        layout.addWidget(self.btn_logs)

        self.setLayout(layout)

    def initServiceAccount(self):
        try:
            DELEGATED_ADMIN_EMAIL = 'support@withfath.com'
            SERVICE_ACCOUNT_FILE = 'service-account.json'
            self.credentials = service_account.Credentials.from_service_account_file(
                SERVICE_ACCOUNT_FILE, scopes=['https://www.googleapis.com/auth/admin.directory.user', 'https://www.googleapis.com/auth/gmail.modify', 'https://www.googleapis.com/auth/gmail.send'])
            self.admin_cred = self.credentials.with_subject(DELEGATED_ADMIN_EMAIL)
            self.admin_service = build('admin', 'directory_v1', credentials=self.admin_cred)
        except Exception as err:
            self.add_log_signal.emit("Google service account initialization failed! Restart application.")

    def initWorkerThread(self):
        self.user_queue_lock = threading.Lock()
        self.work_continue = True
        self.worker_thread = threading.Thread(target=self.work)
        self.worker_thread.start()
        self.add_log_signal.emit("Registration engine started!")

    def initHttpServer(self):
        ssl_context = SSLContext(PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain("bot_ssl.pem", "bot_ssl.key")

        self.httpd = HTTPServer(("", HTTP_PORT), lambda *args, **kwargs: MyRequestHandler(*args, mainwindow=self, **kwargs))
        self.httpd.socket = ssl_context.wrap_socket(self.httpd.socket, server_side=True)

        self.add_log_signal.emit(f"HTTP server started at port {HTTP_PORT}!")
        self.initWorkerThread()
        self.httpd.serve_forever()

    def work(self):
        while self.work_continue:
            user_len = len(self.user_queue)
            i = 0
            while i < user_len:
                try:
                    email = self.user_queue[i]['email']
                    gmail_cred = self.credentials.with_subject(email)
                    gmail_service = build('gmail', 'v1', credentials=gmail_cred)
                    results = gmail_service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=100).execute()
                    messages = results.get('messages', [])
                    if not messages:
                        i = i + 1
                        continue

                    for message in messages:
                        msg = gmail_service.users().messages().get(userId='me', id=message['id']).execute()
                        sender = self.getHeader(msg['payload']['headers'], 'From')
                        if sender and 'corrlinks' in sender.lower():
                            subject = self.getHeader(msg['payload']['headers'], 'Subject')
                            if subject and 'custody' in subject.lower():
                                email_content = self.getMailContent(msg)
                                id_code = self.extractFromContent(email_content, 'Identification Code:')
                                if len(id_code):
                                    if email == CATCHALL_MAIL:
                                        email = self.extractFromContent(email_content, 'Email Address:')
                                        self.add_log_signal.emit(f"CatchAll email received inmate registration on {email}")
                                        splitIdx = subject.find(":") + 1
                                        subject = subject[splitIdx:]
                                        names = subject.split(",")
                                        ln = names[0].strip()
                                        fn = names[1].strip()

                                        inmate_number = self.register_corrlink(email, fn, ln, FIXED_MAIL_PWD, id_code, isCatchAll = True)
                                        if inmate_number:
                                            api_success = self.apiPennedSms('/api/v1/user', {
                                                'name': f"{fn} {ln}",
                                                'inmate_name': f"{fn} {ln}",
                                                'inmate_number': int(inmate_number),
                                                'email': email,
                                                'inmate_email': email,
                                                'inmate_password': FIXED_MAIL_PWD
                                            })
                                            gmail_service.users().messages().modify(
                                                userId='me',
                                                id=message['id'],
                                                body={'removeLabelIds': ['UNREAD']}
                                            ).execute()

                                            if api_success:
                                                threading.Thread(target=self.sendWelcomeLetter, args=(email, FIXED_MAIL_PWD)).start()
                                                self.add_log_signal.emit(f"Premade inmate registration success, inmate number={inmate_number} inmate email={email}")
                                    else:
                                        self.add_log_signal.emit(f"Email {email} received Corrlinks invitation!")
                                        if self.register_corrlink(email, self.user_queue[i]['fn'], self.user_queue[i]['ln'], self.user_queue[i]['pwd'], id_code):
                                            sid = self.user_queue[i]['sid']
                                            pwd = self.user_queue[i]['pwd']

                                            self.user_queue_lock.acquire()
                                            self.user_queue.pop(i)
                                            self.user_queue_lock.release()
                                            i = i - 1
                                            user_len = user_len - 1

                                            self.admin_service.users().delete(userKey=email).execute()
                                            self.user_registered_signal.emit(email)
                                            self.apiPennedSms(f"/api/v1/user/{sid}/update", {
                                                'inmate_password': pwd
                                            })
                                            threading.Thread(target=self.sendWelcomeLetter, args=(email, pwd)).start()
                                break
                except Exception as error:
                    self.add_log_signal.emit(f"While reading emails, met error={error}")
                i = i + 1

            time.sleep(CHECK_INTERVAL)

    def getHeader(self, headers, name):
        for header in headers:
            if header['name'].lower() == name.lower():
                return header['value']
        return None

    def getMailContent(self, msg):
        if 'data' in msg['payload']['body']:
            email_content = self.decode_base64url(msg['payload']['body']['data'])
        else:
            parts = msg['payload']['parts']
            email_content = ""
            for part in parts:
                if 'data' in part['body']:
                    email_content += self.decode_base64url(part['body']['data'])
                elif 'parts' in part:
                    for sub_part in part['parts']:
                        if 'data' in sub_part['body']:
                            email_content += self.decode_base64url(sub_part['body']['data'])
        return email_content

    def decode_base64url(self, data):
        decoded_bytes = base64.urlsafe_b64decode(data + '==')
        return decoded_bytes.decode('utf-8')

    def extractFromContent(self, content, search_str):
        startIdx = content.find(search_str)
        if startIdx < 0:
            return ''

        startIdx += len(search_str)
        endIdx = content.find("\n", startIdx)
        if endIdx < 0:
            endIdx = len(content)

        value = content[startIdx:endIdx].strip()
        return value

    def apiPennedSms(self, url, payload):
        if not self.api_token:
            self.apiGetToken()

        headers = {
            'Authorization': f"Bearer {self.api_token}"
        }
        response = requests.post(f"{API_BASEURL}{url}", headers=headers, json=payload)

        if response.status_code == 401:
            self.apiGetToken()
            response = requests.post(f"{API_BASEURL}{url}", headers=headers, json=payload)
        if response.status_code != 200:
            self.add_log_signal.emit(f"Api call {url} failed, payload={payload}, response={response.text}")
            return False
        return True

    def apiGetToken(self):
        try:
            response = requests.post(f"{API_BASEURL}/oauth/token", json={
                'client_id': '9cc1b125-1ab3-4fcc-a276-0c3594d0590e',
                'client_secret': 'FX8ZTMiwI7cP2QgSxVNUBja0oogfXkteALVGHvuw',
                'grant_type': 'client_credentials'
            })
            self.api_token = response.json()['access_token']
        except Exception as error:
            self.add_log_signal.emit(f"While get api token, met error={error}")

    def createGmail(self, obj):
        unique_id = uuid.uuid4()
        ids = str(unique_id).split('-')
        email = f"user{ids[1][0:2]}{ids[2][0:2]}{ids[3][0:2]}{ids[4][0:2]}@withfath.com"
        fn = obj['fn']
        ln = obj['ln']
        sid = obj['sid']
        semail = obj['semail']
        pwd = FIXED_MAIL_PWD

        self.add_log_signal.emit(f"Online registration request received data={obj}")

        user_body = {
            "primaryEmail": email,
            "name": {
                "givenName": fn,
                "familyName": ln
            },
            "password": pwd,
            "orgUnitPath": "/"
        }

        # Create the user
        try:
            self.admin_service.users().insert(body=user_body).execute()

            new_user = {
                'email': email,
                'fn': fn,
                'ln': ln,
                'semail': semail,
                'pwd': pwd,
                'sid': sid
            }
            self.user_queue_lock.acquire()
            self.user_queue.append(new_user)
            self.user_queue_lock.release()

            self.add_user_signal.emit(new_user)
            self.add_log_signal.emit(f'Inmate email {email} created successfully for subscriber {semail}.')
            self.apiPennedSms(f"/api/v1/user/{sid}/update", {
                'inmate_email': email
            })
            self.sendMail(semail, f"Please inform this email to incarcerated loved one.\n{email}")
        except Exception as error:
            self.add_log_signal.emit(f'{email} creation failed, error={error}')

    def register_corrlink(self, email_address, fn, ln, pwd, id_code, isCatchAll = False):
        isSuccess = False
        chrome_options = uc.ChromeOptions()
        chrome_options.add_argument('--blink-settings=imagesEnabled=false')
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        driver = uc.Chrome(
            driver_executable_path=os.path.join(os.path.dirname(ChromeDriverManager().install()), "chromedriver.exe"),
            options=chrome_options,
        )
        try:
            driver.get('https://www.corrlinks.com/SignUp.aspx')
            initial_url = driver.current_url

            # Fill out the form fields
            # Find the elements by their name attribute, ID, or other attributes
            el_fname = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_firstNameTextBox1')
            el_lname = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_lastNameTextBox1')
            el_email = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_emailAddressTextBox')
            el_email_confirm = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_emailAddressTextBox2')
            el_pwd = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_passwordTextBox')
            el_pwd_confirm = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_confirmPasswordTextBox')
            el_id_code = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_requestCodeTextBox')

            # Input data into the form fields
            el_fname.send_keys(fn)
            el_lname.send_keys(ln)
            el_email.send_keys(email_address)
            el_email_confirm.send_keys(email_address)
            el_pwd.send_keys(pwd)
            el_pwd_confirm.send_keys(pwd)
            el_id_code.send_keys(id_code)

            el_check_age = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_tocCheckBox')
            el_check_age.click()

            # Submit the form
            time.sleep(5)
            submit_button = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_nextButton')
            submit_button.click()

            WebDriverWait(driver, 60).until(EC.url_changes(initial_url))

            if 'Default.aspx' in driver.current_url:
                self.add_log_signal.emit(f"{email_address} Corrlinks registration success!")
                if isCatchAll:
                    try:
                        driver.get("https://www.corrlinks.com/RegisterInmate.aspx")
                        el = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_AddInmatesUC_InmateAddGridView')
                        els = el.find_elements(By.CSS_SELECTOR, ":scope tr")
                        el = els[1]
                        els = el.find_elements(By.CSS_SELECTOR, ":scope td")
                        return els[0].text
                    except Exception as error:
                        pass
                else:
                    isSuccess = True
            else:
                self.add_log_signal.emit(f"{email_address} Corrlinks registration failed!")

        except Exception as error:
            self.add_log_signal.emit(f"{email_address} while Corrlinks registration met error={error}.")
        finally:
            driver.quit()
        return isSuccess

    def send_welcome(self, email, pwd):
        chrome_options = uc.ChromeOptions()
        chrome_options.add_argument('--blink-settings=imagesEnabled=false')
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        driver = uc.Chrome(
            driver_executable_path=os.path.join(os.path.dirname(ChromeDriverManager().install()), "chromedriver.exe"),
            options=chrome_options,
        )
        try:
            driver.get('https://www.corrlinks.com/login.aspx')
            initial_url = driver.current_url

            el_email = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_loginUserNameTextBox')
            el_pwd = driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_loginPasswordTextBox')
            el_email.send_keys(email)
            el_pwd.send_keys(pwd)
            driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_loginButton').click()

            WebDriverWait(driver, 60).until(EC.url_changes(initial_url))

            driver.get('https://www.corrlinks.com/NewMessage.aspx')
            driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_addressBox_addressTextBox').click()
            el = driver.find_element(By.CSS_SELECTOR, '#ctl00_mainContentPlaceHolder_addressBox_outerPanel tr:not(:first-child)')
            el = el.find_element(By.CSS_SELECTOR, ':scope input')
            el.click()
            el = driver.find_element(By.CSS_SELECTOR, '#ctl00_mainContentPlaceHolder_addressBox_outerPanel #ctl00_mainContentPlaceHolder_addressBox_okButton')
            el.click()
            time.sleep(1)
            driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_subjectTextBox').send_keys('Welcome')
            time.sleep(1)
            driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_messageTextBox').send_keys(WELCOME_TEXT)
            driver.find_element(By.ID, 'ctl00_mainContentPlaceHolder_sendMessageButton').click()
            time.sleep(2)

            return True
        except Exception as error:
            return False
        finally:
            driver.quit()

    def sendWelcomeLetter(self, email, pwd):
        self.add_log_signal.emit(f"Welcome letter will be sent to {email} after 1 hour")
        time.sleep(3600)
        
        retry = 0
        while (retry < MAX_SENDWELCOME_RETRY):
            if (self.send_welcome(email, pwd)):
                break
            retry = retry + 1
        self.add_log_signal.emit(f"Welcome letter is sent to {email}!")

    def sendMail(self, email, content):
        gmail_service = build('gmail', 'v1', credentials=self.admin_cred)
        message = MIMEText(content)
        message['to'] = email
        message['from'] = 'support@withfath.com'
        message['subject'] = 'Pennedsms Service'
        raw = base64.urlsafe_b64encode(message.as_bytes())
        raw = raw.decode()
        message = {'raw': raw}
        gmail_service.users().messages().send(userId='me', body=message).execute()

    def openLogFile(self):
        subprocess.run(["notepad.exe", LOG_FILE])

    def addLog(self, text):
        if self.log_cnt >= 100:
            self.log_widget.clear()
            self.log_cnt = 0

        self.log_file.write(f"{text}\n")
        self.log_file.flush()
        self.log_widget.appendPlainText(text)
        self.log_cnt = self.log_cnt + 1

    def addUserToList(self, user):
        list_item = QListWidgetItem(self.list_mails)

        mailitem_widget = MailItemWidget()
        mailitem_widget.setMail(user['email'])
        mailitem_widget.setInfo(user['fn'], user['ln'], user['pwd'])

        list_item.setSizeHint(mailitem_widget.sizeHint())
        self.list_mails.setItemWidget(list_item, mailitem_widget)

    def registerUser(self, email):
        for i in range(self.list_mails.count()):
            mailitem_widget = self.list_mails.itemWidget(self.list_mails.item(i))
            if mailitem_widget.getMail() == email:
                self.list_mails.takeItem(i)
                break

    def beforeQuit(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.work_continue = False
        self.worker_thread.join()
        self.log_file.close()

if __name__ == '__main__':
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    app.aboutToQuit.connect(window.beforeQuit)
    sys.exit(app.exec_())
