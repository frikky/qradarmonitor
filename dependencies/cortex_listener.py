import requests
import os

import config as cfg

class cortex_listen(object):
    def __init__(self, logpath):
        self.logpath = logpath
        self.verify_logpath()

    # ABSOLUTE PATHS PLS
    def verify_logpath(self):
        try:
            os.stat(self.logpath)
        except OSError:
            self.logpath = "../%s" % self.logpath
    
    # Removes a list of items from logfile
    def remove_item(self, cortexid):
        #returns if neither ID or name are part of read
        if not cortexid:
            return False

        filedata = self.get_cortex_scan_list()
        # Loops and finds the item
        data = []
        for items in filedata:
            if len(items) <= 1:
                continue

            objects = items.split(",")
            if objects[2] in cortexid:
                continue

            if objects[4].endswith("\n"):
                objects[4] = objects[4][:-1]

            data.append(",".join(objects))
            
        with open(self.logpath, "w+") as tmp:
            tmp.write("\n".join(data))

    # Replaces a scanID in logfile if new scan is initiated
    def replace_cortex_scanID(self, old_id, new_id):
        filedata = self.get_cortex_scan_list()
        if not filedata:
            return
            
        data = []
        for item in filedata:
            if len(item) <= 1:
                continue

            objects = item.split(",")

            # Actually replaces
            if objects[2] == old_id:
                objects[2] = new_id

            if objects[4].endswith("\n"):
                objects[4] = objects[4][:-1]

            data.append(",".join(objects))

        # Writes back to file
        with open(self.logpath, "w+") as tmp:
            tmp.write("\n".join(data))
            
    # Adds to the logfile
    def write_to_file(self, data, datatype, cortexjob, artifactID, analyzer):
        if analyzer.endswith("\n"):
            analyzer = analyzer[:-1]

        filedata = self.get_cortex_scan_list()
        filedata.append("%s,%s,%s,%s,%s" % (data, datatype, cortexjob, artifactID, analyzer))

        with open(self.logpath, "w+") as tmp:   
            tmp.write("\n".join(filedata)) 

    # Gets a job based on ID
    def get_specific_cortex_job(self, job_id):
        cortexip = cfg.cortexip
        data = requests.get("http://%s/api/job/%s" % (cortexip, job_id))
        if not data.ok:
            return False

        return data.json()

    # Returns full cortex scan list - not in use
    def get_cortex_scan_list(self):
        with open(self.logpath, "r") as tmp:
            data = tmp.read().split("\n")

        return data

    # Finds failed scan results and rescans with TheHive
    def find_failed_cortex_jobs(self):
        # Creates login for new analysis 
        scanlist = self.get_cortex_scan_list()
        if not scanlist:
            return False

        request_session = self.create_hive_login_session()

        item_to_remove = []
        # Grabs items as csv format ish
        for item in scanlist:
            split_item = item.split(",") 
            if len(split_item) <= 1:
                continue

            jobdata = self.get_specific_cortex_job(split_item[2])

            # Removes an item from logfile if it doesn't exist anymore
            # Often the case if > 24 hours have gone by
            if not jobdata:
                item_to_remove.append(split_item[2])
                continue
            
            # Removes from scanresult
            if jobdata["status"] == "Success":
                item_to_remove.append(split_item[2])
                continue
            elif jobdata["status"] == "InProgress":
                continue

            # Failure scans go here
            data = {"id": split_item[3]}
            if split_item[4].endswith("\n"):
                analyzer = [split_item[4][:-1]]
            else:
                analyzer = [split_item[4]]

            ret_analysis = self.run_specific_analysis(request_session, data, analyzer)
            if ret_analysis:
                self.replace_cortex_scanID(split_item[2], ret_analysis["cortexJobId"])
            
        # Removes all successfully scanned data
        self.remove_item(item_to_remove)

    # Login to bypass API restrictions (its in their todo for API)
    def create_hive_login_session(self):
        r = requests.session()

        # WE MOZILLA NOW
        r.headers["User-Agent"] = \
            "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"

        # Hardcoded tokens
        r.headers["X-XSRF-TOKEN"] = cfg.TheHiveCookie
        r.cookies["XSRF-TOKEN"] = cfg.TheHiveCookie

        baseurl = "http://%s" % cfg.hiveip
        authdata = {"user":cfg.hiveusername,"password":cfg.hivepassword}

        ret = r.post("%s%s" % (baseurl, "/api/login"), data=authdata)

        if ret.ok:
            return r
        else:
            return False

    # Runs analysis on a specific object
    # item = dict, cur_analyzers=list
    def run_specific_analysis(self, request_session, item, cur_analyzers):
        # Attempt analysis
        target = "http://%s%s" % (cfg.hiveip, "/api/connector/cortex/job")

        # Runs through available analyzers
        for analyzer in cur_analyzers:
            cortexdata = {
                "cortexId": "cortex1",
                "artifactId":item["id"],
                "analyzerId":analyzer
            }

            try:
                analyzethis = request_session.post(target, data=cortexdata, timeout=5)
            except requests.exceptions.ReadTimeout:
                return False 

            analyze = analyzethis.json()

            # Does multiple jobs
            if len(cur_analyzers) > 1:
                self.write_to_file(item["data"], item["dataType"], analyze["cortexJobId"], item["id"], analyzer)
                continue

            # FIX - running just one scanner. SAVE INBETWEEN
            if analyzethis.ok:
                return analyze
            else:
                return False

    # Analyze a specific observable in TheHive
    def run_cortex_analyzer(self, datatype, data, case_data):
        request_session = self.create_hive_login_session()
        
        # FIX - Idk what to do here yet
        if not request_session:
            return False

        analyzers = self.get_cortex_analyzers_datatype(datatype)
        cur_analyzers = []

        available = cfg.available_analyzers
        for item in analyzers:
            for analyzer in available:
                if analyzer in item["name"].lower():
                    cur_analyzers.append(item["id"])

        for item in case_data:
            self.run_specific_analysis(request_session, item, cur_analyzers)

        # Closes login session
        request_session.close()

    # Returns avaialbe analyzers for a given datatype
    def get_cortex_analyzers_datatype(self, type):
        return requests.get("http://%s/api/analyzer/type/%s" % (cfg.cortexip, type)).json()

if __name__ == "__main__":
    asd = cortex_listen("log/cortex_analysis.log")
    asd.find_failed_cortex_jobs()
