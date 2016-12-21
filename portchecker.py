#!/usr/bin/env python3

import socket
import ipaddress
import threading
import queue
import logging
import logging.handlers
import argparse


def check_connection(tryHost, tryPorts):
  TIMEOUT = 0.5
  tryHost = str(tryHost)
  openedPorts = []
  
  logger.debug(threading.currentThread().getName() + " check started " + tryHost)
  for tryPort in tryPorts:
    try:
      s = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
      s.settimeout(TIMEOUT)
      if s.connect_ex((tryHost,tryPort)) == 0:
        openedPorts.append( tryPort )
      s.close

    except socket.timeout:
      print(tryHost + " Timeout")
    except socket.error:
      print("Something go wrong")
  
  logger.debug(threading.currentThread().getName() + " check finished " + tryHost)
  return openedPorts

def check_connection_queue(tryPorts,hQueue):
  TIMEOUT = 0.5
  openedPorts = []
  while not hQueue.empty():
    tryHost = str(hQueue.get())
    openedPorts = []
      
    logger.debug(threading.currentThread().getName() + " check started " + tryHost)
    for tryPort in tryPorts:
      try:
        s = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((tryHost,tryPort)) == 0:
          openedPorts.append( tryPort )
        s.close

      except socket.timeout:
        print(tryHost + " Timeout")
      except socket.error:
        print("Something go wrong")
    if openedPorts:
      logger.info("{}: {}".format(tryHost,str(openedPorts)))
    logger.debug(threading.currentThread().getName() + " check finished " + tryHost)
    hQueue.task_done()
  return 

parser = argparse.ArgumentParser(description='just check open ports')
parser.add_argument('-d','--dest',
                    action="append",
                    dest='nets',
                    default=[],
                    nargs='+',
                    help="hosts to scan"
)
parser.add_argument('-p','--ports', 
                    action="append",
                    dest='ports',
                    type=int,
                    default=[],
                    nargs='+',
                    help="ports to scan"
)
parser.add_argument('-w', '--workers',
                    action="store",
                    dest='workers',
                    default=1,
                    type=int,
                    nargs=1,
                    help="number of workers for parallel scan"
)
#print(parser.parse_args())
pArguments = parser.parse_args()
if pArguments.nets: print('hosts to scan: {!r}'.format(pArguments.nets))
if pArguments.ports: print('ports to scan: {!r}'.format(pArguments.ports))
if pArguments.workers: print('workers to scan: {!r}'.format(pArguments.workers))

ports = sorted(list(set([item for sublist in pArguments.ports for item in sublist])))
print("ports to scan: {}".format(ports))


LOG_FILENAME = 'portchecker.log'
#logging.basicConfig(
#  filename=LOG_FILENAME,
#  #level=logging.INFO,
#  level=logging.DEBUG,
#  datefmt='%Y-%m-%d %H:%M:%S',
#  format='%(asctime)s %(levelname)-8s %(message)s',
#)

logger = logging.getLogger('portchecker')
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter(
  '%(asctime)s %(levelname)-8s %(message)s',
  '%Y-%m-%d %H:%M:%S',
)
consoleFormatter = logging.Formatter(
  '%(message)s',
)

handler = logging.handlers.RotatingFileHandler(
  LOG_FILENAME,
  maxBytes=1024**2,
  backupCount=5,
)
handler.setFormatter(formatter)
handler.doRollover()

consoleHandler = logging.StreamHandler()
consoleHandler.setLevel(logging.INFO)
consoleHandler.setFormatter(consoleFormatter)

logger.addHandler(handler)
logger.addHandler(consoleHandler)

#HOSTS = [ 'localhost', 'ya.ru']
#NETS = ['46.229.164.192/26','46.229.165.0/26','192.243.51.64/26','213.174.146.0/25','213.174.146.128/25']
#PORTS = [22, 80, 443]
#PORTS = list(range(1024))
#WORKERS = 21

### USING THREADS
hostsQueue = queue.Queue()

for NET in NETS:
  for HOST in ipaddress.ip_network(NET):
    hostsQueue.put(HOST)

logger.debug("Number of hosts in queue: " + str(hostsQueue.qsize()))

for i in range(WORKERS):
  logger.debug("Current active workers: " + str(threading.activeCount()))
  t = threading.Thread(target=check_connection_queue, args=(PORTS,hostsQueue))
  t.start()

main_thread = threading.currentThread()
for t in threading.enumerate():
  if t is main_thread:
      continue
  t.join()

hostsQueue.join()


### WITHOUT THREADS
#for HOST in HOSTS:
#  portsForHost = check_connection(HOST,PORTS)
#  if portsForHost:
#    print("{}: {}".format(str(HOST), str(portsForHost)))
##  except KeyboardInterrupt:
##    break
#
