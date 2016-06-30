from flask import Flask, request
import threading
import json


class rest_sensor(object):

    def __init__(self):
        self.app = Flask(__name__)
        self.positive_callbacks = []
        self.negative_callbacks = []

        def start():
            @self.app.route("/detection/positive", methods=['PUT'])
            def positive():
                self.handle_put(self.positive_callbacks, request)

            @self.app.route("/detection/negative", methods=['PUT'])
            def negative():
                self.handle_put(self.negative_callbacks, request)

            self.app.run(host='0.0.0.0')

        threading.Thread(target=start).start()

    def register_positive_callback(self, cb):
        self.positive_callbacks.append(cb)

    def register_negative_callback(self, cb):
        self.negative_callbacks.append(cb)

    def handle_put(self, lst, req):
        if req.method == 'PUT':
            recieved_data = {
                'nw_src': req.form['nw_src'],
                'tp_src': req.form['tp_src'],
                'nw_dst': req.form['nw_dst'],
                'tp_dst': req.form['tp_dst']
            }
            for callback in lst:
                callback(received_data)
