#!/usr/bin/env python3

import argparse
from concurrent import futures
import ipaddress
import logging
import logging.handlers
import queue
import time
import socket
import sys
import threading

def ports_check(tryHost, tryPorts, timeout):
  openedPorts = []
  for tryPort in tryPorts:
    try:
      s = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
      s.settimeout(timeout)
      if s.connect_ex((tryHost,tryPort)) == 0:
        openedPorts.append( tryPort )
      s.close
    except socket.timeout:
      logger.debug("{}:{} connection timeout".format(tryHost,tryPort))
    except socket.error:
      logger.debug("{}:{} other socket error".format(tryHost,tryPort))
  #if openedPorts: logger.debug("found opened ports for host {}: {}".format(tryHost, openedPorts))
  return openedPorts 

def check_connection_queue(tryPorts, hQueue, TIMEOUT, portsCheckSlice):
  openedPorts = []
  while not hQueue.empty():
    tryHost = str(hQueue.get())
    openedPorts = []
    logger.debug("[{}] [{}] starting check {}".format(runTime(), threading.currentThread().getName(), tryHost))

    oPorts = futures.ThreadPoolExecutor(max_workers=portsCheckSlice)
    wait_oPorts = [oPorts.submit(ports_check, tryHost, tryPorts[i:i+portsCheckSlice], TIMEOUT) for i in range(0,len(tryPorts),portsCheckSlice)] 
    for f in futures.as_completed(wait_oPorts):
      #logger.debug("opened ports {}: {}".format(tryHost, f.result()))
      openedPorts.extend(f.result())

    if openedPorts:
      openedPorts.sort()
      logger.info("{}: {}".format(tryHost,str(openedPorts)))
    logger.debug("[{}] [{}] check finished {}".format(runTime(), threading.currentThread().getName(), tryHost))
    hQueue.task_done()
  return 

timeStart = time.time()
runTime = lambda: round(time.time() - timeStart, 2)

parser = argparse.ArgumentParser(description='just check open ports')
parser.add_argument('-c', '--concurrency',
                    action="store",
                    dest='concurrency',
                    default=100,
                    type=int,
                    help="connections per worker (default: 100)"
)
parser.add_argument('-d','--dest',
                    action="append",
                    dest='nets',
                    default=[],
                    nargs='+',
                    help="hosts in CIDR notation to scan (default: 127.0.0.1). example: -d 10.1.1.0/24 -d 10.1.1.2 -d 10.1.1.0/30 10.1.1.5"
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
                    help="ports to scan (default: 1-65535). example: -p 21 -p22-25 -p 80 443 8080-8090"
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

list_flatten = lambda x: list(set([item for sublist in x for item in sublist]))


PORTS = pArguments.ports

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
else:
  PORTS = list(range(65536))


NETS = pArguments.nets

if pArguments.dest_file: 
  try:
    nets_file = open(pArguments.dest_file, 'r')
    NETS.append([NET.rstrip('\n') for NET in nets_file])
  except:
    logger.debug("could not open file: {}".format(pArguments.dest_file))

if NETS:
  NETS = sorted(list_flatten(NETS))
else:
  NETS.append('127.0.0.1')

logger.debug("ports: {}".format(PORTS))
logger.debug("ports count: {}".format(len(PORTS)))
logger.debug("nets: {}".format(NETS))
logger.debug("timeout: {} sec".format(pArguments.timeout))
logger.debug("workers: {}".format(pArguments.workers))
logger.debug("concurrency: {}".format(pArguments.concurrency))
logger.debug("logging level: {}".format(logger_level))


hostsQueue = queue.Queue()
try:
  [hostsQueue.put(HOST) for NET in NETS for HOST in ipaddress.ip_network(NET)]
except ValueError as host_err:
  logger.info("failed add {} [SKIPPED]".format(host_err)) 
except:
  logger.info("something goes wrong with parsing hosts")
logger.debug("number of hosts in queue: {}".format(str(hostsQueue.qsize())))

for i in range(pArguments.workers):
  logger.debug("current active workers: {}".format(str(threading.activeCount())))
  t = threading.Thread(target=check_connection_queue, args=(PORTS,hostsQueue, pArguments.timeout, pArguments.concurrency))
  t.start()

main_thread = threading.currentThread()
for t in threading.enumerate():
  if t is main_thread:
      continue
  t.join()

hostsQueue.join()

logger.info("finished in {} seconds".format(runTime()))

