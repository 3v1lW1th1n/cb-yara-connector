from celery import Celery, bootsteps
import globals

app = Celery()
app.conf.task_serializer = "pickle"
app.conf.result_serializer = "pickle"
app.conf.accept_content = {"pickle"}

import yara
import logging
import traceback
import datetime
import configparser
import os
import shutil
import hashlib
from analysis_result import AnalysisResultSuccess, AnalysisResultError, AnalysisResultNotAvailable
from cbapi.response.models import Binary
from cbapi.response.rest_api import CbResponseAPI
import globals
import multiprocessing

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

#Adapted from oriely
class ReadWriteLock:
    """ A lock object that allows many simultaneous "read locks", but
    only one "write lock." """

    def __init__(self):
        self._read_ready = multiprocessing.Condition(multiprocessing.Lock(  ))
        self._readers = 0

    def acquire_read(self):
        """ Acquire a read lock. Blocks only if a thread has
        acquired the write lock. """
        self._read_ready.acquire()
        try:
            self._readers += 1
        finally:
            self._read_ready.release()

    def release_read(self):
        """ Release a read lock. """
        self._read_ready.acquire()
        try:
            self._readers -= 1
            if not self._readers:
                self._read_ready.notifyAll()
        finally:
            self._read_ready.release()

    def acquire_write(self):
        """ Acquire a write lock. Blocks until there are no
        acquired read or write locks. """
        self._read_ready.acquire()
        while self._readers > 0:
            self._read_ready.wait()

    def release_write(self):
        """ Release a write lock. """
        self._read_ready.release()



compiled_yara_rules = None
compiled_rules_lock = ReadWriteLock()        

g_config = dict()


def verify_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    if not config.has_section('general'):
        logger.error("Config file does not have a \'general\' section")
        return False

    if 'yara_rules_dir' in config['general']:
        globals.g_yara_rules_dir = config['general']['yara_rules_dir']

    if 'cb_server_url' in config['general']:
        globals.g_cb_server_url = config['general']['cb_server_url']

    if 'cb_server_token' in config['general']:
        globals.g_cb_server_token = config['general']['cb_server_token']

    if 'broker_url' in config['general']:
        app.conf.update(
            broker_url=config['general']['broker_url'],
            result_backend=config['general']['broker_url'])

    return True


def add_worker_arguments(parser):
    parser.add_argument('--config-file', default='yara_worker.conf', help='Yara Worker Config')


app.user_options['worker'].add(add_worker_arguments)


class MyBootstep(bootsteps.Step):

    def __init__(self, worker, config_file='yara_worker.conf', **options):
        super().__init__(self)
        verify_config(config_file)

        # g_yara_rules_dir = yara_rules_dir


app.steps['worker'].add(MyBootstep)


@app.task
def update_yara_rules_remote(compiled_rules_data):
    global compiled_yara_rules
    globa. compiled_rules_lock
    try:
        new_rules_object = yara.load(compiled_rules_data)
    except Exception as e:
        logger.debug(f"Error loading rules into worker : {str(e)}")
    else: 
        compiled_rules_lock.acquire_write()
        compiled_yara_rules = new_rules_object
        compiled_rules_lock.release_write()

@app.task
def analyze_binary(md5sum):
    global compiled_rules_lock
    global compiled_yara_rules
    logger.debug("{}: in analyze_binary".format(md5sum))

    cb = None

    try:
        cb = CbResponseAPI(url=globals.g_cb_server_url,
                           token=globals.g_cb_server_token,
                           ssl_verify=False,
                           timeout=5)
    except Exception as e:
        error_msg = f"Exception occured connection to cbr from worker task {str(e)}"
        logger.debug(error_msg)
        return [AnalysisResultError(md5sum,error_msg=error_msg)]

    binary_query = cb.select(Binary).where(f"md5:{md5sum}").first()

    if binary_query is None:
        return [AnalysisResultError(md5sum,error_msg=f"Couldn't find binary for md5sum {md5sum}")]

    binary_data = None    
    try:
        binary_data = binary_query[0].file.read()
    except IOError as e:
        return [AnalysisResultError(md5sum,error_msg=str(e))]

    try:
        # matches = "debug"
        compiled_yara_rules.acquire_read()
        matches = yara_rules.match(data=binary_data, timeout=30)
        compiled_rules_lock.release_read()
        analysis_results = []
        for match in matches:
            r = match.rule
            score = match.meta.get('score',100)
            logger.debug(f{"Rule {r} matched {md5sum} with {score} !"})
            analysis_results.append(AnalysisResultSuccess(md5sum,score))
        return analysis_results      
    except yara.TimeoutError as yte:
        #
        # yara timed out
        #
        logger.debug("Timed out scanning {md5sum} {yte.message}")
        return [AnalysisResultError(md5sum,error_msg=f"{yte.message}")]
    except yara.Error as ye:
                #
                # Yara errored while trying to scan binary
                #
        logger.debug("Yara error when scanning {md5sum} {ye.message}")
        return [AnalysisResultError(md5sum,error_msg=f"{ye.message}")]        
    except Exception as e: 
        logger.debug(f"Something went wrong scanning {md5sum}....{str(e)}")
        logger.debug(traceback.format_exc())

        return [AnalysisResultError(md5sum,error_msg=str(e))]