#
#  ida/proxy.py
#  Tweak Studio
#
#  Created by Tanner Bennett on 2021-05-24
#  Originated from file created by Ethan Arbuckle on 2021-03-05
#  Copyright (c) 2021 Ethan Arbuckle and Tanner Bennett. All rights reserved.
#
#  References and libraries used:
#  Demangle inhibitor flags: https://github.com/rcx/ida-scripts/blob/master/cfg/ida.cfg
#  Sark: https://github.com/tmr232/Sark
#  FIDL: https://github.com/fireeye/FIDL
#

import json
import traceback
import http.client
import os
import http.server as https

try:
    import thread
except ImportError:
    import dummy_thread as thread

from globals import wantsShutdown
from endpoints import kEndpoints

from idaapi import load_plugin, autoWait

load_plugin('hexx64')
load_plugin('hexarm64')
autoWait()

class RequestHandler(https.BaseHTTPRequestHandler):
    def do_POST(self):
        global wantsShutdown
        content_length = int(self.headers.get("Content-Length", 0))
        posted_data = json.loads(self.rfile.read(content_length)) if content_length > 0 else {}

        data_response = None
        error = None

        for handler in kEndpoints:
            if self.path == handler.PATH:
                try:
                    data_response = handler.run(**posted_data)
                    self.respond(200, data_response)
                except TypeError as e:
                    error = str(e) + '\n' + traceback.format_exc()
                    self.respond(500, None, error)
                except Exception as e:
                    error = str(e) + '\n' + traceback.format_exc()
                    self.respond(500, None, error)
                
                if wantsShutdown():
                    def _shutdown():
                        self.server.shutdown()
                    thread.start_new_thread(_shutdown, ())
                
                break
        else:
            self.respond(404, None, "Unknown endpoint: " + self.path)
    
    def respond(self, status, data, error=None):
        response = {"data": data}
        if error:
            response["error"] = error
        
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response, default=lambda o: '').encode("utf-8"))
            


if __name__ == "__main__":

    # Create server with first available port
    server = https.HTTPServer(("", 0), RequestHandler)
    
    # Notify extension of our port
    myPort = server.server_address[1]
    callback = http.client.HTTPConnection('localhost', int(os.environ["EXT_PORT"]))
    headers = {'Content-type': 'application/json'}
    body = json.dumps({'port': myPort})
    callback.request('POST', '/tweakstudio/ida', body, headers)

    # Begin serving requests
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    exit()
