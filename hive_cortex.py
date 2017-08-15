def create_hive_login_session(self):
    r = requests.session()

    # WE MOZILLA NOW
    r.headers["User-Agent"] = \
        "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0"

    # Token doesn't seem to matter as long as it has this format
    # Needs both header and cookie
    r.headers["X-XSRF-TOKEN"] = \
        "702c3bcb9ccdcb89d6f99b975d4c04113681fb42-1502714690921-f0a9e3e297fcc9d90a085c86"
    r.cookies["XSRF-TOKEN"] = \
        "702c3bcb9ccdcb89d6f99b975d4c04113681fb42-1502714690921-f0a9e3e297fcc9d90a085c86"

    baseurl = "http://%s" % cfg.hiveip
    authdata = {"user":cfg.hiveusername,"password":cfg.hivepassword}

    ret = r.post("%s%s" % (baseurl, "/api/login"), data=authdata)

    if ret.ok:
        return r
    else:
        return False

# Analyze a specific observable in TheHive
def run_cortex_analyzer(self, datatype, data, case_data):
    request_session = self.create_hive_login_session()
    
    # Idk what to do here yet
    if not request_session:
        return False

    analyzers = self.get_cortex_analyzers_datatype(datatype)

    # Attempt analysis
    target = "http://%s%s" % (cfg.hiveip, "/api/connector/cortex/job")

    # Runs through available analyzers
    for analyzer in cur_analyzers:
        cortexdata = {
            "cortexId": "cortex1",
            "artifactId":case_data["id"],
            "analyzerId":analyzer
        }

        analyze = request_session.post(target, data=cortexdata, timeout=5)
        print analyze.text
        
        logging.info("%s: Started analysis of item %s" % (self.get_time, data))
        print "%s: Started analysis of item %s" % (self.get_time(), data)

    # Closes login session
    request_session.close()
