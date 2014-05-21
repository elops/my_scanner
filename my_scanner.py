#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__  = "Hrvoje Spoljar <hrvoje.spoljar@gmail.com>"
__description__ = "Fanotify based IDS"
__title__ = "my_scanner"


import multiprocessing
import fanotify             # https://bitbucket.org/mjs0/pyfanotify/
import logging
import getopt
import fcntl
import time
import sys
import os
from subprocess import call, Popen, PIPE
from collections import deque

# General rules 
__sig_path=os.path.dirname(os.path.realpath(__file__))
__rules=__sig_path + '/sig/malware.sig'


# regex checker; we use Popen/egrep solution because it is fast... no scripting regex machine beats it
# for more info check : http://swtch.com/~rsc/regexp/regexp1.html
def check_popen(file_name):
    process = Popen(['/bin/egrep', '-Hf', __rules, file_name] , shell=False, stdout=PIPE, stderr=PIPE)
    try:
        out, err = process.communicate()
    except Exception as e:
        logger.error(e)

    if process.returncode == 0:
        logger.debug('found cookie\n %s' %out)


# Periodic status report task function.
def status(coalesce_queue, worker_queue, ):
    while True:
        t=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        os.system('clear')
        worker_qlen = worker_queue.qsize()
        coalesce_qlen = coalesce_queue.qsize()

        factor =  int((max([worker_qlen,coalesce_qlen,6400])*1.1 / 80) + 1)

        worker_draw = int(worker_qlen)/factor
        coalesce_draw = int(coalesce_qlen)/factor

        logger.info("""%s 
        Worker queue:
[%-6d] %s>
        Coalescing queue: 
[%-6d] %s>
                        """ %(t, worker_queue.qsize(), ('='*worker_draw), coalesce_queue.qsize(), ('='*coalesce_draw), ))
        time.sleep(.2)


# fanoitfy
def fawatch(coalesce_queue, ):
    fan = fanotify.FileAccessNotifier()
    fan.watch_mount('/')
    logger.info('Starting fanotify...')
    while True:
        item = fan.read_event()
        if not item.startswith('/tmp'):
            coalesce_queue.put(item)


# Magic :)
def coalesce(coalesce_queue, worker_queue, ):
        """ This function coalesces data that we get from fanotify watch and feeeds it to worker queue. 
            Simple tweaks here can be used for throttling of scanning...

         try read from coalesce_q (timeout 0.1)
          - put data in blackbox if not in box already
         except empty
         finally
          - check if we need to pop anything from blackbox
        """

        coalesce_time = 5           # period over which we coalesce data
        coalesce_wait = 0.1         # this is how long we wait trying to get item from coalesce_queue
        coalesce_list = deque([])   # storage for our data which will be coalesced 

        while True:
            duplicate = False

            try:
                item = coalesce_queue.get(True,coalesce_wait)

                # scan through our coalesce_list to see if entry which we want to add already exists...
                for element in coalesce_list:
                    if item in element[1]:
                        duplicate = True    
                        break

                # if it does not exist append this element to 'coalesce_list'
                if not duplicate:
                    coalesce_list.append((int(time.time()*(1/coalesce_wait)),item))
                    logger.debug('sent to blackbox [%d] >> %s ' %(len(coalesce_list), item) )


            except multiprocessing.managers.Queue.Empty:
                # queue was empty
                pass


            finally:
                # We check if there are any items in 'blackbox' which are old enough to be popped 
                curtime = int(time.time()*(1/coalesce_wait))
                if len(coalesce_list) > 0:
                    # logger.debug('coalesce_list has %d items...' %len(coalesce_list))
                    # check if oldest element should be popped... 
                    if curtime - coalesce_list[0][0] > coalesce_time*(1/coalesce_wait):
                        logger.debug('Found old items, about to popleft() some stuff')
                        while len(coalesce_list) > 0:
                            if curtime - coalesce_list[0][0] > coalesce_time*(1/coalesce_wait):
                                item = coalesce_list.popleft()[1]
                                worker_queue.put(item)
                                logger.debug('sent to work queue [%d]> %s' %(worker_queue.qsize(),item))
                            else:
                                break


# digger funct, these guys handle the dirty work
def worker(queue):
    while True:
        try:
            file_name = queue.get()

        except multiprocessing.managers.Queue.Empty:
            file_name = None

        if file_name:
            if os.path.exists(file_name):
                logger.debug('-1 = [%s]> %s' %(queue.qsize(),file_name))
                check_popen(file_name)
                try:
                    queue.task_done()
                except Exception as e:
                    logger.error(e)


def usage():
    print("""
    %s

    %s

    Usage : %s [ARGS]
    -h  --help      Show this
    -v  --verbose   Enable verbosity ( multiple switches increase verbosity ) 

    report bugs to  : %s
    """ %(__title__,__description__,sys.argv[0], __author__))


if __name__ == '__main__':

    logger = multiprocessing.log_to_stderr()
    logger.setLevel(30)

    # Standard getopt stuff...
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hv", ["verbose","help"])
    except getopt.GetoptError, err:
        # print help information and exit:
        print str(err) # will print something like "option -a not recognized"
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-v", "--verbose"):
            # multiple -v will get us more verbosity...
            if logger.getEffectiveLevel() > 10:
                logger.setLevel(logger.getEffectiveLevel() - 10)
        else:
            assert False, "unhandled option"



    # Check if rules file exists...
    if not os.path.exists(__rules):
        logger.error("Can't find rules file %s" %__rules)
        sys.exit(2)

    # Locking stuff
    __my_lock = open('/tmp/' + __title__ + '.lock', 'w')
    try:
        fcntl.flock(__my_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        logger.error("Can't get exclusive write-lock, exiting ...")
        sys.exit(1)


    # Multiprocessing stuff
    logger.debug('Cores : %s' %multiprocessing.cpu_count())
    proclist = []

    manager        = multiprocessing.Manager()
    worker_queue   = manager.Queue()
    coalesce_queue = manager.Queue()

    # TODO: start configurable number of processes , currently starts '3'
    for i in xrange(3):
        worker_p = multiprocessing.Process(name='Worker-' + str(i), target=worker, args=(worker_queue, )) 
        worker_p.daemon = True
        worker_p.start()
        proclist.append(worker_p)

    # status thread
    status_p = multiprocessing.Process(name='Status', target=status, args=(coalesce_queue, worker_queue, ))
    status_p.daemon = True
    status_p.start()
    proclist.append(status_p)

    # FAnotify thread
    fanotify_p = multiprocessing.Process(name='Fanotify', target=fawatch, args=(coalesce_queue, ))
    fanotify_p.daemon = True
    fanotify_p.start()
    proclist.append(fanotify_p)

    # Coalescing thread
    coalesce_p = multiprocessing.Process(name='Coalescing', target=coalesce, args=(coalesce_queue, worker_queue, ))
    coalesce_p.daemon = True
    coalesce_p.start()
    proclist.append(coalesce_p)

    # Start'em all!
    for i in proclist:
        try:
            i.join()
        except KeyboardInterrupt:
            logger.info('Caught CTRL+C ; Exiting...')
            for i in xrange(3):
                i.terminate()
                # Release fnctl lock
                __my_lock.close()


# EOF
