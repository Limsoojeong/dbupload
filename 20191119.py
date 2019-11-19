import sys
import struct
import pymysql
import select
import time
import numpy as np
import keras
from keras.models import load_model
from keras.preprocessing import sequence
from urllib.parse import unquote

input_dim = 129
output_dim = 2
max_seq = 256

connect = pymysql.connect(host='182.162.109.227', user='root',
password='number1rhddbqnstjr!', port=33306, db='feed_info', charset='utf8')

class batch_predict:

    def __init__(self, input_dim, output_dim):
        print("load_model")
        self.model = load_model("weights-05-0.9984.hdf5")
        self.max_wait_time = 0.001
        self.batch_size = 16
        self.input_dim = input_dim
        self.output_dim = output_dim

        self.batch_x = []
        self.batch_id = []
        self.wait_start = None
        self.count = 0

    def _queue_data(self, x_data, identity):
        self.batch_x.append(x_data)
        self.batch_id.append(identity)

    def _database(self, ident, prob, result):
        cur2 = connect.cursor()
        sql2 = "insert into waf_detect_log_test(idx,prob,result) values (%s, %s, %s)"
        cur2.execute(sql2, (ident, prob, result))
        connect.commit()

    def _data(self, batch_y):
        result = 0
        for i in range(len(self.batch_x)):
            ident = self.batch_id[i]
            prob = float(batch_y[i][1])
            if prob >= 0.5:
                result = 1
            else:
                result = 0
            self._database(ident, prob, result)

    def _encoding(self, batch_x, max_seq):
        encoded_batch_x = []
        for x in batch_x:
            encoded = []
            for i in range(len(x)):
                num = ord(x[i]) + 1
                if num >= 128:
                    encoded.append(128)
                else:
                    encoded.append(num)
            encoded_batch_x.append(encoded)
        encoded_batch_x = sequence.pad_sequences(encoded_batch_x, maxlen=max_seq, padding='pre', truncating='post')
        encoded_batch_x = keras.utils.to_categorical(encoded_batch_x, num_classes=self.input_dim, dtype='int32')
        return encoded_batch_x

    def predict(self, identity, data):
        if data: 
            self._queue_data(data, identity)
            if len(self.batch_x) == 1:
                self.wait_start = time.time()  

        if len(self.batch_x) > 0 and \
            (len(self.batch_x) >= self.batch_size or \
             (time.time() - self.wait_start) >= self.max_wait_time):
            # predict
            batch_x = self._encoding(self.batch_x, max_seq)
            batch_y = self.model.predict(batch_x)
            self._data(batch_y)
            # reset
            self.batch_x = []
            self.batch_id = []
        else:
            return 

cur = connect.cursor(pymysql.cursors.DictCursor)
sql = "select idx, path, request_header, request_body from waf_detect_log_1911"
cur.execute(sql)
connect.commit()
rows = cur.fetchall()

bp = batch_predict(input_dim, output_dim)

for row in rows:
    ident = row['idx']
    header = row['request_header'][:3]
    body = row['request_body']

    if header == '%50':
        if body and not body.isspace():
            x = unquote(row['request_body'])
        else:
            x = unquote(row['path'])
    else:
        x = unquote(row['path'])
    data = x.encode()

    x_data = data.decode()
    bp.predict(ident, x_data)
    #print(x_data)