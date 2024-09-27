import requests
import random
import string
import hashlib
import os
import base64
import json
import sys
import time
import signal
from datetime import datetime

client = requests.Session()
client.verify = False

reset = "\033[0m"
intense_red = "\033[31;1m"
intense_green = "\033[32;1m"
intense_blue = "\033[34;1m"
intense_yellow = "\033[33;1m"
intense_cyan = "\033[36;1m"
intense_magenta = "\033[35;1m"

def exit_handler(sig, frame):
    print(f"\n\n\n{intense_red} Existing KeyboardInterrupt..... {reset}")
    sys.exit(-1)

signal.signal(signal.SIGINT, exit_handler)

def slow_print(text):
    for char in text:
        sys.stdout.write(char)
        time.sleep(0.1)
        sys.stdout.flush()
    sys.stdout.write("\n")

def print_banner():
    print("───────────────────────────────────────────────────────────────")
    print(f"{intense_yellow}Welcome advanced password manager {reset}")
    print("───────────────────────────────────────────────────────────────")
    print(f"{intense_magenta}{intense_blue}")
    print("┌─────────────────────────────────────────────────────────────┐")
    print(f"{intense_magenta}│                                                             │")
    print(f"{intense_magenta}│{intense_cyan}Author: {reset} {intense_green}[ https://t.me/Jamaal_ahmedy ]{reset}                      │")
    print(f"{intense_magenta}│                                                             │")
    print("└─────────────────────────────────────────────────────────────┘")
    print(f"{reset}")

def MD5_Hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

def encode_base64(data):
    return base64.b64encode(data.encode()).decode()

def decode_base64(data):
    return base64.b64decode(data).decode()

def generate_otp(length=8):
    digits = string.digits
    return ''.join(random.choices(digits, k=length))

def send_otp(token, chat_id, otp):
    decode_token = base64.b64decode(token).decode()
    decode_chatid = base64.b64decode(chat_id).decode()
    url = f"https://api.telegram.org/bot{decode_token}/sendMessage"
    data = {"chat_id": decode_chatid, "text": f"Your OTP code is: {otp}"}
    try:
        response = client.post(url, data=data)
        if response.status_code == 200:
            print(f"{intense_green}[+] Code successfully sent.{reset}")
        else:
            print(f"{intense_red}[-] Failed to send{reset}")
    except Exception as e:
        print(f"Error: {e}")

def load_json_file(filename):
    with open(filename, "r") as file:
        return json.load(file)

def save_json_file(filename, data):
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)

def main():
    if not os.path.exists("file.json"):
        master_password = input(f"{intense_yellow}Enter new master password: {reset}")
        token_user = input(f"{intense_yellow}Enter token bot: {reset}")
        chat_id_user = input(f"{intense_yellow}Enter chat_id: {reset}")

        hashed_password = MD5_Hash(master_password)
        token_b64 = base64.b64encode(token_user.encode()).decode()
        chat_idb64 = base64.b64encode(chat_id_user.encode()).decode()

        data = {"master_password": hashed_password, "token": token_b64, "chat_id": chat_idb64}

        save_json_file("file.json", data)
        print(f"{intense_magenta}Setup complete! Your data has been saved to file.json.{reset}")
    else:
        data = load_json_file("file.json")
        master_password = input(f"{intense_yellow}Enter your master password: {reset}")
        hashed_password = MD5_Hash(master_password)

        if hashed_password == data["master_password"]:
            otp = generate_otp()
            send_otp(data["token"], data["chat_id"], otp)

            user_otp = input(f"{intense_yellow}Please Enter otp: {reset}")

            if user_otp == otp:
                slow_print(f"{intense_green}OTP verified successfully!{reset}")

                while True:
                    print(f"{intense_green}──────────────────────────────────────────────{reset}")
                    print(f"\n{intense_blue}1. Save password.{reset}")
                    print(f"{intense_blue}2. Display saved passwords.{reset}")
                    print(f"{intense_blue}3. Exit.{reset}")
                    print(f"{intense_green}──────────────────────────────────────────────{reset}")

                    choice = input(f"{intense_yellow}\nChoice (1-3): {reset}")

                    if choice == "1":
                        username_or_email = input(f"{intense_yellow}Enter Username or Email: {reset}")
                        password = input(f"{intense_yellow}Enter Password: {reset}")

                        encode_username_or_email = encode_base64(username_or_email)
                        encode_password = encode_base64(password)

                        timestamp = datetime.now().strftime("%a - %Y - %m - %d %H:%M:%S")  # Add timestamp

                        if os.path.exists("password.json"):
                            passwords = load_json_file("password.json")
                        else:
                            passwords = {}

                        passwords[encode_username_or_email] = {
                            "password": encode_password,
                            "timestamp": timestamp
                        }

                        save_json_file("password.json", passwords)
                        print(f"{intense_green}Password saved successfully!{reset}")
                    elif choice == "2":
                        if os.path.exists("password.json"):
                            passwords = load_json_file("password.json")
                            print(f"{intense_green}Saved passwords:{reset}")
                            for encode_username_or_email, data in passwords.items():
                                decoded_email_or_username = decode_base64(encode_username_or_email)
                                decoded_password = decode_base64(data["password"])
                                timestamp = data["timestamp"]
                                print(f"{intense_green}", "-" * 40)
                                print(f"{intense_cyan}Email/Username: {decoded_email_or_username}{reset}")
                                print(f"{intense_cyan}Password: {decoded_password}{reset}")
                                print(f"{intense_cyan}Saved on: {timestamp}{reset}")
                                print(f"{intense_green}", "-" * 40)
                        else:
                            print(f"{intense_red}[-] No passwords saved yet.")

                    elif choice == "3":
                        print(f"{intense_red}Exiting ...{reset}")
                        break
                    else:
                        print(f"{intense_red}Invalid choice, please try again.{reset}")
            else:
                print(f"{intense_red}Incorrect OTP. Exiting program.{reset}")
        else:
             print(f"{intense_red}Incorrect password. Exiting program.{reset}")

if __name__ == "__main__":
    print_banner()
    main()
