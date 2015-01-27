from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import IBurpExtenderCallbacks

from java.io import PrintWriter
from java.util import List
from java.util import ArrayList
from javax.swing import JMenuItem
from javax.swing import JOptionPane
from java.awt.event import ActionListener

class BurpExtender(IBurpExtender):

    EXTENSION_NAME = "Extension: Select text"

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

        # register ourselves as a message editor tab factory
        callbacks.registerContextMenuFactory(CustomContextMenu(self))

        self._stdout.println("%s loaded!" % BurpExtender.EXTENSION_NAME)

class CustomContextMenu(IContextMenuFactory, ActionListener):
    AVAILABLE_TOOLS = (
        IBurpExtenderCallbacks.TOOL_PROXY,
    )

    AVAILABLE_CONTEXT = (
        IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
        IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE
    )

    def __init__(self, extender):
        self._extender = extender

    def can_create_menu(self):
        if (self._invocation.getToolFlag() in CustomContextMenu.AVAILABLE_TOOLS):
            if self._invocation.getInvocationContext() in CustomContextMenu.AVAILABLE_CONTEXT:
                if len(self._invocation.getSelectionBounds()) == 2:
                    if len(self._invocation.getSelectedMessages()) == 1:
                        return True

        return False

    def createMenuItems(self, invocation):
        self._invocation = invocation

        if self.can_create_menu():
            self._item = JMenuItem("Select text!")
            self._item.addActionListener(self)

            return [self._item]

        return []

    def actionPerformed(self, event):
        if event.getActionCommand() == self._item.getText():
            start, end = self._invocation.getSelectionBounds()
            message = self._invocation.getSelectedMessages()[0]
            ctx = self._invocation.getInvocationContext()

            message = message.getRequest() if ctx == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST else message.getResponse()
            selected_text = self._extender._helpers.bytesToString(message)[start:end]

            JOptionPane.showMessageDialog(None, selected_text, "Selected text", JOptionPane.INFORMATION_MESSAGE)
            self._extender._stdout.println("[+] Selected text:\n%s" % selected_text)
