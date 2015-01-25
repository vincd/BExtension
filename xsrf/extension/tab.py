from burp import IBurpExtender
from burp import IHttpListener

from java.io import PrintWriter

b2s = lambda r: "".join(map(chr, r))

def update_URI(request, uri):
    start_index = request.find(' ')
    end_index = request.find(' ', start_index+1)

    return request[:start_index+1] + uri + request[end_index:]

class BurpExtender(IBurpExtender, IHttpListener):

    EXTENSION_NAME = "Extension: Edit XSRF token on the fly!"

    HOST = "localhost"
    PORT = 8081
    XSRF_PARAM_NAME = "xsrf"

    def log(self, msg):
        self._stdout.println("[+] %s" % msg)

    def error(self, msg):
        self._stdout.println("[-] %s" % msg)
        self._stderr.println("[-] %s" % msg)

    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
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

        self.log("%s loaded!" % BurpExtender.EXTENSION_NAME)

    #
    # implement IHttpListener
    #
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:

            # get the HTTP service for the request
            httpService = messageInfo.getHttpService()

            if BurpExtender.HOST == httpService.getHost():
                # get the request as a byte array
                request = messageInfo.getRequest()
                self.log("Original request:\n%s\n" % b2s(request))

                # find the XSRF token
                xsrf_param = self._helpers.getRequestParameter(request, BurpExtender.XSRF_PARAM_NAME)

                if xsrf_param:
                    self.log("Request XSRF token = %s" % xsrf_param.getValue())

                    # we need the send a GET request to the server to get a valid XSRF token
                    # POST -> GET and byte[] -> String
                    new_request = b2s(self._helpers.toggleRequestMethod(request))
                    # change the URI to the index page to get a new XSRF token
                    new_request = update_URI(new_request, "/")

                    self.log("XSRF request:\n%s\n" % new_request)

                    # send this request
                    response = self._callbacks.makeHttpRequest(
                        httpService,
                        self._helpers.stringToBytes(new_request)
                    )

                    if response:
                        response = b2s(response.getResponse())
                        self.log("XSRF response:\n%s\n" % response)

                        # name="xsrf" value="4eWgmB8635ywkrezNOHZQVC8WPTNM+2Qe5BesgJfxKY=" />
                        pattern = 'name="xsrf" value="'
                        token_len = 44
                        new_token = response[len(pattern) + response.find(pattern):]
                        new_token = new_token[:token_len]

                        self.log("New token = %s" % new_token)

                        # create a new param for the XSRF token
                        new_param = self._helpers.buildParameter(
                            xsrf_param.getName(),
                            new_token,
                            xsrf_param.getType()
                        )
                        # update the original request with the new XSRF token
                        update_request = self._helpers.updateParameter(request, new_param)
                        self.log("Update request:\n%s\n" % b2s(update_request))

                        # notify burp with the edited request
                        messageInfo.setRequest(update_request)
                    else:
                        self.error("Can't fetch URL to get a new token")
                else:
                    self.log("Could not find any XSRF token")

        return
