from flask import Flask
from flask import render_template
from flask import request
from flask import session

import random
from base64 import b64encode

app = Flask(__name__)

current_xsrf_token = ""

def gen_xsrf_token():
    token = b64encode("".join(map(chr, [random.randint(0, 255) for i in xrange(32)])))
    print "Gen: %s" % token

    return token

@app.route("/", methods=[ "GET" ])
def hello():
    global current_xsrf_token

    new_xsrf = gen_xsrf_token()

    print "New XSRF %s" % new_xsrf
    current_xsrf_token = new_xsrf

    return render_template('index.html', xsrf=new_xsrf)

@app.route("/login", methods=[ "POST" ])
def login():
    global current_xsrf_token

    username = request.form['username']
    passwd = request.form['passwd']
    xsrf = request.form['xsrf']
    session_xsrf = current_xsrf_token.replace('+', ' ')

    # set new XSRF token
    current_xsrf_token = gen_xsrf_token()

    print "LOGIN %s - %s" % (xsrf, session_xsrf)
    if xsrf == session_xsrf:
        if username == "yolo" and passwd == "swag":
            return render_template('page.html')
        else:
            return render_template('error.html', error="Bad credentials")
    else:
        return render_template('error.html', error="Bad XSRF token")


if __name__ == "__main__":
    app.run(debug=True, host='localhost', port=8081)
