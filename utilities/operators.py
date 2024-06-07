# Set log levels
from shutil import copyfile, move
import shutil
from os.path import isfile, join
from os import listdir
import os
import sys
import json
import time

LOGLEVELS = {"NONE": 0, "CRITICAL": 1, "EXCEPTION": 2,
             "ERROR": 3, "WARNING": 4, "INFO": 5, "STATS": 6, "DEBUG": 7}
LOGLEVEL = LOGLEVELS["STATS"]
LOGFILE = None
SERVER_LOGS_STARTED = False


from datetime import datetime, timezone

"""
Class that defines operations in files, directories, clases, ...
"""
class op:
    @staticmethod
    def json_string_to_object(json_string):
        data = json.loads(json_string)
        return data

    @staticmethod
    def to_json(source_object,indent=0,ensure_ascii=True):
        return json.dumps(obj=source_object,indent=indent,ensure_ascii=ensure_ascii)
    
    @staticmethod
    def to_json_file(source_object,json_file_path,file_open_mode="w",indent=2):
        tmp_json_string=op.to_json(source_object=source_object,indent=indent)
        op.write_to_file(data=tmp_json_string, filePath=json_file_path,openMode=file_open_mode, end="")
        
    @staticmethod
    def read_json_file(filePath,encoding="utf-8"):
        data=None
        f = open(filePath,"r",encoding=encoding)
        data = json.load(f)
        f.close()
        
        return data  
      
    @staticmethod
    def get_filedatetime(zone=timezone.utc):
        return datetime.now(zone).strftime("%Y%m%d_%H%M%S")


    @staticmethod
    def timestamp(zone=timezone.utc, string=False):
        timestamp = datetime.timestamp(datetime.now(zone))
        
        if (string):
            return str(timestamp)
        

        return timestamp
    
    @staticmethod
    def get_datetime(zone=timezone.utc, string=False):
        date = datetime.now(zone)
        if (string):
            return str(date)
        
        return date
    
    @staticmethod
    def start_log(log_file=None):
        global LOGFILE
        if(log_file == None):
            log_file = f"generator-{op.timestamp()}.log"
            LOGFILE = log_file
        openMessage = "Starting Log Messages..."
        op.write_to_file(data=openMessage, filePath=log_file,
                       openMode="w+", end="\n")

    @staticmethod
    def value_empty(obj):
        return "" if obj == None or obj == "" else obj

    # Method to set value none by default
    @staticmethod
    def value_none(obj):
        return None if obj == None or obj == "" else obj

    # print logs to a file
    @staticmethod
    def print_log(message, log_type="DEBUG", e=None):
        # global LOGLEVELS, LOGLEVEL
        # If the log level requested is lower than the actual log level
        # LOGLEVELS: NONE=0, CRITICAL=1, EXCEPTION=2, ERROR=3, WARNING=4, INFO=5, STATS=6, DEBUG=7
        # LOGLEVEL: STATS=6
        # if LOGLEVEL < LOGLEVELS[log_type]:
        #     return None

        # Add the log description and exception if not empty
        log_info = "["+log_type+"]:"
        if(e != None):
            log_info += "[" + str(e) + "]."
        
        # Print the log
        log_data = " ".join([log_info, message])
        op.write_to_file(data=log_data, filePath=LOGFILE, openMode="a+", end="\n")

    # Init dynamically the new class
    @ staticmethod
    def create_class(newClass, *args, **kwargs):
        # Get slices
        slices = newClass.split('.')

        # Count the number of slices
        lenSlices = len(slices)

        # Check if the number of slices
        if lenSlices == 1:
            slices.append(slices[0])

        # Import Class
        importedClass = __import__(".".join(slices[:-1]))

        # For every component add attributes
        for component in slices[1:]:
            importedClass = getattr(importedClass, component)

        # Create the class
        return importedClass(*args, **kwargs)

    @ staticmethod
    def path_exists(pathName):
        pathFile = os.path.exists(pathName)
        return pathFile

    @ staticmethod
    def make_dir(nameDir, permits=0o777):
        if op.path_exists(nameDir):
            return True
        os.makedirs(nameDir, permits)
        return True
    
    @ staticmethod
    def delete_dir(nameDir):
        if not op.path_exists(nameDir):
            return False
        
        shutil.rmtree(nameDir)
    @ staticmethod
    def copy_file(src, dst):
        return copyfile(src, dst)

    @ staticmethod
    def move_file(src, dst):
        return move(src, dst)

    @ staticmethod
    def to_string(inputFile, openmode="r", encoding=sys.stdout.encoding):
        str = open(inputFile, openmode, encoding=encoding).read()
        return str

    @ staticmethod
    def delete_file(filePath):
        if not op.path_exists(filePath):
            return None

        os.remove(filePath)
        return True

    @ staticmethod
    def get_path_without_file(filePath):
        return os.path.dirname(filePath)

    @ staticmethod
    def write_to_file(data, filePath, openMode="r", end=""):
        if(data == "" or data == None):
            return None

        # data = data + end
        # path = op.get_path_without_file(filePath)

        # if path == None or not op.path_exists(path):
        #     op.make_dir(path)

        file = open(filePath, openMode, encoding=sys.stdout.encoding)
        file.write(data)
        file.write(end)
        file.close()
        return True
    
    @ staticmethod
    def wait(seconds):
        return time.sleep(seconds)
    
    @staticmethod
    def get_attribute(sourceObject,attrPath,defaultValue=None,pathSep="."):
        tmpRet=defaultValue
        if sourceObject == None:
            return tmpRet
    
        if pathSep == None or pathSep == "":
            return tmpRet
    
        tmpParts=attrPath.split(pathSep)
        if tmpParts == None or tmpParts == "":
            return tmpRet
        for part in tmpParts:
            if not part in sourceObject:
                return tmpRet
            sourceObject=sourceObject[part]
        tmpRet=sourceObject
        return tmpRet
    
    @staticmethod
    def print_message(message, info_level="INFO", log_enabled=False):
        
        global SERVER_LOGS_STARTED
        if log_enabled and message is not None:
            if not SERVER_LOGS_STARTED:
                op.start_log()
                SERVER_LOGS_STARTED=True
            op.print_log(message, info_level)
        
        # print message on console
        print("[" + info_level + "] - " + message)
    
    
    @staticmethod
    def search_element_by_field(array, id, field="id"):
        return next((x for x in array if x[field] == id), None)