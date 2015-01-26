from burp import IBurpExtender
from burp import IHttpListener

from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener):

    EXTENSION_NAME = "Extension: Edit XSRF token on the fly!"

    HOST = "localhost"
    XSRF_PARAM_NAME = "xsrf"
    XSRF_URI = "/"

    def find_token(self, response):
        # name="xsrf" value="4eWgmB8635ywkrezNOHZQVC8WPTNM+2Qe5BesgJfxKY=" />
        pattern = 'name="%s" value="' % BurpExtender.XSRF_PARAM_NAME
        token_len = 44
        token = response[len(pattern) + response.find(pattern):]
        token = token[:token_len]

        return token

    def update_request(self, request, fn):
        request_info = self._helpers.analyzeRequest(request)
        headers = request_info.getHeaders()
        msg_body = request[request_info.getBodyOffset():]

        headers, msg_body = fn(headers, msg_body)
        message = self._helpers.buildHttpMessage(headers, msg_body)

        return message

    def updateURI(self, request, uri):
        def fn(headers, msg_body):
            http_info = headers.get(0).split(' ')
            headers.set(0, " ".join([http_info[0], uri, http_info[2]]))

            return headers, msg_body

        return self.update_request(request, fn)

    def addHeader(self, request, header, value):
        def fn(headers, msg_body):
            self.log("headers:")
            for header in headers:
                self.log("  %s" % header)

            headers.add('%s: %s' % (header, value))

            return headers, msg_body

        return self.update_request(request, fn)

    def log(self, msg):
        self._stdout.println("[+] %s" % msg)

    def error(self, msg):
        self._stdout.println("[-] %s" % msg)
        self._stderr.println("[-] %s" % msg)

    def log_request(self, name, request):
        self.log("%s:\n%s\n%s\n%s" % (name, "-" * 10, self._helpers.bytesToString(request), "-" * 10))

    def registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # obtain our output and error streams
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)

        # set our extension name
        callbacks.setExtensionName(BurpExtender.EXTENSION_NAME)

        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)

        self.log("%s loaded!\n  Host: %s\n  PARAM: %s\n  URL: %s" % (
            BurpExtender.EXTENSION_NAME,
            BurpExtender.HOST,
            BurpExtender.XSRF_PARAM_NAME,
            BurpExtender.XSRF_URI))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # get the HTTP service for the request
        httpService = messageInfo.getHttpService()

        # only process requests to *HOST*
        if messageIsRequest and BurpExtender.HOST == httpService.getHost():
            # get the request as a byte array
            request = messageInfo.getRequest()

            # find the *XSRF* parameter
            xsrf_param = self._helpers.getRequestParameter(request, BurpExtender.XSRF_PARAM_NAME)

            if xsrf_param:
                self.log_request("Original request", request)
                self.log("Original XSRF token = %s" % xsrf_param.getValue())

                # send a GET request to *URI* to get a valid XSRF token
                xsrf_request = self.updateURI(self._helpers.toggleRequestMethod(request), BurpExtender.XSRF_URI)
                self.log_request("XSRF request", xsrf_request)

                # send this request to get a valid XSRF token
                xsrf_response = self._callbacks.makeHttpRequest(httpService, xsrf_request)

                if xsrf_response:
                    xsrf_response = xsrf_response.getResponse()
                    self.log_request("XSRF response", xsrf_response)

                    # find the valid token in the page
                    new_token = self.find_token(self._helpers.bytesToString(xsrf_response))
                    self.log("New XSRF token = %s" % new_token)

                    # create a new param for the XSRF token
                    new_param = self._helpers.buildParameter(xsrf_param.getName(), new_token, xsrf_param.getType())
                    # update the original request with the new XSRF token
                    edited_request = self._helpers.updateParameter(request, new_param)
                    self.log_request("Update request", edited_request)

                    # edit the current request with the new token
                    messageInfo.setRequest(edited_request)
                else:
                    self.error("Can't fetch URL to get a new token")

        return
