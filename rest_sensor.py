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
            print 1
            recieved_data = {}
            print 2
            received_data['nw_src'] = req.form['nw_src']
            print 3
            received_data['tp_src'] = req.form['tp_src']
            print 4
            received_data['nw_dst'] = req.form['nw_dst']
            print 5
            received_data['tp_dst'] = req.form['tp_dst']
            print 6
            for callback in lst:
                print 7
                callback(received_data)
