import os
import threading
from subprocess import call

def call_receive(iface):
    call(['python', 'receive_si.py', iface])


for iface in filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/')):
    processThread = threading.Thread(target=call_receive, args=(iface,))
    processThread.start()