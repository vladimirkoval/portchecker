#!/usr/bin/env python3

import argparse
import ipaddress
import logging
import logging.handlers
import queue
import time
import socket
import sys
import threading

def check_connection_queue(tryPorts, hQueue, TIMEOUT):
  openedPorts = []
  while not hQueue.empty():
    tryHost = str(hQueue.get())
    openedPorts = []
      
    logger.debug("{} starting check {}".format(threading.currentThread().getName(), tryHost))
    for tryPort in tryPorts:
      try:
        s = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        if s.connect_ex((tryHost,tryPort)) == 0:
          openedPorts.append( tryPort )
        s.close

      except socket.timeout:
        logger.debug("{}:{} connection timeout".format(tryHost,tryPort))
      except socket.error:
        logger.debug("{}:{} other socket error".format(tryHost,tryPort))

    if openedPorts:
      logger.info("{}: {}".format(tryHost,str(openedPorts)))
    logger.debug(threading.currentThread().getName() + " check finished " + tryHost)
    hQueue.task_done()
  return 

timeStart = time.time()
runTime = lambda: round(time.time() - timeStart, 2)

parser = argparse.ArgumentParser(description='just check open ports')
parser.add_argument('-d','--dest',
                    action="append",
                    dest='nets',
                    default=[],
                    nargs='+',
                    help="hosts in CIDR notation to scan. example: -d 10.1.1.0/24 -d 10.1.1.2 -d 10.1.1.0/30 10.1.1.5"
)
parser.add_argument('-D', '--dest-file',
                    action="store",
                    dest='dest_file',
                    type=str,
                    help="input file with hosts in CIDR, one network or host per line"
)
parser.add_argument('-o', '--output',
                    action="store",
                    dest='output',
                    type=str,
                    help="write output to <file> instead of STDOUT"
)
parser.add_argument('-p','--ports', 
                    action="append",
                    dest='ports',
                    type=str,
                    default=[],
                    nargs='+',
                    help="ports to scan. example: -p 21 -p22-25 -p 80 443 8080-8090"
)
parser.add_argument('-P', '--ports-file',
                    action="store",
                    dest='ports_file',
                    type=str,
                    help="input file with ports, one port or port range per line"
)
parser.add_argument('-t', '--timeout',
                    action="store",
                    dest='timeout',
                    default=0.5,
                    type=float,
                    help="connection timout in seconds for each port"
)
parser.add_argument('-v', '--verbose',
                    action="count",
                    help="verbose level"
)
parser.add_argument('-w', '--workers',
                    action="store",
                    dest='workers',
                    default=1,
                    type=int,
                    help="number of workers for parallel scan"
)
#print(parser.parse_args())
pArguments = parser.parse_args()
#logging.basicConfig(
#  filename=LOG_FILENAME,
#  #level=logging.INFO,
#  level=logging.DEBUG,
#  datefmt='%Y-%m-%d %H:%M:%S',
#  format='%(asctime)s %(levelname)-8s %(message)s',
#)

logger = logging.getLogger('portchecker')

if pArguments.output:
  logFileFormatter = logging.Formatter(
    #'%(asctime)s %(levelname)-8s %(message)s',
    '%(asctime)s %(message)s',
    '%Y-%m-%d %H:%M:%S',
  )
  handler = logging.handlers.RotatingFileHandler(
    pArguments.output,
    maxBytes=1024**2,
    backupCount=5,
  )
  handler.setFormatter(logFileFormatter)
  handler.doRollover()
  logger.addHandler(handler)
else:
  consoleFormatter = logging.Formatter(
    '%(message)s',
  )
  consoleHandler = logging.StreamHandler()
  consoleHandler.setFormatter(consoleFormatter)
  logger.addHandler(consoleHandler)

if pArguments.verbose: 
  if pArguments.verbose > 1:
    logger_level = 'DEBUG'
  elif pArguments.verbose > 0:
    logger_level = 'INFO'
#  elif pArguments.verbose > 2:
#    logger.setLevel(logging.WARNING)
#  elif pArguments.verbose > 1:
#    logger.setLevel(logging.ERROR)
else:
  logger_level = 'INFO'

logger.setLevel(logger_level)
#consoleHandler.setLevel(logger_level)

list_flatten = lambda x: list(set([item for sublist in x for item in sublist]))

if pArguments.ports: 
  PORTS = pArguments.ports
else:
  PORTS = []

if pArguments.ports_file:
  try:
    ports_file = open(pArguments.ports_file, 'r')
  except:
    logger.debug("could not open file: {}".format(pArguments.ports_file))
  try:
    PORTS.append([PORT.rstrip('\n') for PORT in ports_file])
  except:
    logger.info("ports definition wrong: {} [SKIPPED]".format(PORT))

if PORTS:
  PORTS_TMP = []
  for PORT in list_flatten(PORTS):
    if '-' in str(PORT):
      portRange = str(PORT).split('-')
      if len(portRange) > 2:
        sys.exit("ports range definition wrong: {}".format(PORT))
      try:
        PORTS_TMP.append(list(range(int(portRange[0]),int(portRange[1])+1)))
      except:
        logger.info("ports definition wrong: {} [SKIPPED]".format(PORT))
    else:
      try:
        PORTS_TMP.append([int(PORT)])
      except:
        logger.info("ports definition wrong: {} [SKIPPED]".format(PORT))
  PORTS = sorted(list_flatten(PORTS_TMP))
  logger.debug("ports: {}".format(PORTS))
else:
  sys.exit("no ports to scan")

if pArguments.nets:
  NETS = pArguments.nets
else:
  NETS = []

if pArguments.dest_file: 
  try:
    nets_file = open(pArguments.dest_file, 'r')
    NETS.append([NET.rstrip('\n') for NET in nets_file])
  except:
    logger.debug("could not open file: {}".format(pArguments.dest_file))

if NETS:
  NETS = sorted(list_flatten(NETS))
  logger.debug("nets: {}".format(NETS))
else:
  sys.exit("no hosts to scan")

if pArguments.timeout: 
  TIMEOUT = pArguments.timeout
  logger.debug("timeout: {} sec".format(TIMEOUT))

if pArguments.workers: 
  WORKERS = pArguments.workers
  logger.debug("workers: {}".format(WORKERS))

logger.debug("logging level: {}".format(logger_level))

#HOSTS = [ 'localhost', 'ya.ru']
#NETS = ['46.229.164.192/26','46.229.165.0/26','192.243.51.64/26','213.174.146.0/25','213.174.146.128/25']
#PORTS = [22, 80, 443]
#PORTS = list(range(1024))
#WORKERS = 21

hostsQueue = queue.Queue()
[hostsQueue.put(HOST) for NET in NETS for HOST in ipaddress.ip_network(NET).hosts()]

logger.debug("number of hosts in queue: {}".format(str(hostsQueue.qsize())))

for i in range(WORKERS):
  logger.debug("current active workers: {}".format(str(threading.activeCount())))
  t = threading.Thread(target=check_connection_queue, args=(PORTS,hostsQueue,TIMEOUT))
  t.start()

main_thread = threading.currentThread()
for t in threading.enumerate():
  if t is main_thread:
      continue
  t.join()

hostsQueue.join()

logger.info("finished in {} seconds".format(runTime()))

