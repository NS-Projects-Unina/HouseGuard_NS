#script per l'aggiornamento delle liste

import redis
import os
from threading import Thread, Lock
import time
import logging

class DAO:
    def __init__(self, db_name):
        self.db_name = db_name
        self.db_int = os.getenv(db_name)
        self.empty = True
        self.logger = logging.getLogger(__name__)
    
    def is_empty(self):
        return self.empty

    def get_db_connection(self):
        db_int = self.db_int
        redis_cli = redis.Redis(
            host=os.getenv('REDIS_HOST', '127.0.0.1'),
            port=6379,
            decode_responses=True,
            db = db_int
            )
        connection = redis_cli.ping()
        return redis_cli
    
    def load_data(self, data = {}):
        self.empty = False
        redis_cli = self.get_db_connection()
        redis_cli.mset(data)
        redis_cli.close()  

class UpdaterThread(Thread):
    def __init__(self, updateTime, control):
        self.updateTime = updateTime
        self.control = control
        self.logger = logging.getLogger(__name__)
        Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(self.updateTime)
            controlName = type(self.control).__name__
            self.logger.info(f"UpdaterThread {controlName}: Aggiornamento periodico in corso...")
            self.control.load_data(force_update=True)
            self.logger.info(f"UpdaterThread {controlName}: Aggiornamento completato.")