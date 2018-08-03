# -*- coding: utf-8 -*-
import boto3
import json
import datetime
import os
import logging
import zlib
from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
SLACK_CHANNEL = os.environ['slackChannel']
LOG_URL = os.environ['logStreamUrl']
HOOK_URL = boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext'].decode('utf-8')

logs = boto3.client('logs')
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    
    data = zlib.decompress(b64decode(event['awslogs']['data']), 16+zlib.MAX_WBITS)
    data_json = json.loads(data)
    log_group = data_json['logGroup']
    
    #対象Function名は"cbr_*"
    func_from = log_group.find("cbr_")
    
    if func_from > 0:
        
        #対象Function名
        function_name = log_group[func_from:]
        
        #エラー発生日付の抽出（JST変換）
        date =  datetime.datetime.fromtimestamp(int(str(data_json['logEvents'][0]['timestamp'])[:10])) + datetime.timedelta(hours=9)
        
        #エラーメッセージの抽出
        content = data_json['logEvents'][0]['message']
        msg_from = content.find("message:") + 10
        msg_to = content.find("code:") -5
        err_msg = content[msg_from:msg_to]
        
        #Log Stream URL
        log_url = LOG_URL + log_group + ";stream=" + data_json['logStream']
        
        #Slack投稿内容
        message = "```[発生日] " + str(date) + "\n" + "[不審者] " + function_name + "\n" + "[状況] " + err_msg + "\n" + "[情報] " + log_url + "```"
    
        #slack post
        try:
            slack_message = {
                'channel': SLACK_CHANNEL,
                'text': message
            }
            req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
            response = urlopen(req)
            response.read()
            logger.info("Message posted to %s", slack_message['channel'])
    
        except HTTPError as e:
            logger.error("Request failed: %d %s", e.code, e.reason)
        except URLError as e:
            logger.error("Server connection failed: %s", e.reason)
    else:
        context.done()
        logger.info("エラーなし")