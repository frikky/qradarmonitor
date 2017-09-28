import os
import re
import sys
import ast
import json
import time
import socket
import logging
import netaddr
import datetime
import pickledb
import requests
import subprocess
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseTask, CaseObservable 

import dependencies.config as cfg
from dependencies.cortex_listener import cortex_listen

"""
    The part below is setitng up default logging, 
    certificates, disabling uneccesary warnings etc.
"""
dir_path = os.path.dirname(os.path.realpath(__file__))

sys.path.append('%s/dependencies' % dir_path)
from customer import Customer
import urllib

# Add multiple logging systems.
requests.packages.urllib3.disable_warnings(\
requests.packages.urllib3.exceptions.InsecureRequestWarning)


log_path = "%s/log/" % dir_path
if not os.path.exists(log_path):
    os.makedirs(log_path)
    open("%salarm.log" % (log_path), "w+").close()

try:
    logging.basicConfig(filename='%s/log/alarm.log' % dir_path, level=logging.DEBUG)
    if len(sys.argv) > 1: 
        if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
        	os.system('cls' if os.name == 'nt' else 'clear')
except IOError as e:
    print("Might be missing permissions.\n%s" % e)
    try:
        sys.exit(0)
    except SystemExit:
        os._exit(0)

logging.getLogger("requests").setLevel(logging.INFO)
logging.getLogger("urllib3").setLevel(logging.INFO)

json_time = 0
resetcounter = 0

class Offense(object):
    """
        Class used for handling offenses and customers. 
        Uses customer.py to handle each and every customer in the configuration file.
    """

    def __init__(self):
        self.customers = []
        self.db_status = False
        if cfg.TheHive:
            self.hive = TheHiveApi("http://%s" % cfg.hiveip, cfg.hiveusername, 
                            cfg.hivepassword, {"http": "", "https": ""})
            self.cortex_log_path = "log/cortex_analysis.log"
            self.cortex_listener = cortex_listen(self.cortex_log_path)

    # Function only in use when either customer_values.db does not exists or is empty
    def db_setup(self):
        """
	    Creates db for a customer if it doesn't exist.	
        """
        database = "%s/database/customer_values.db" % dir_path
        if not os.path.isfile(database):
            open(database, 'w+').close()

        try:
            self.db = pickledb.load(database, False)
        except pickledb.simplejson.scanner.JSONDecodeError:
            # Remove file, and recreate
            os.remove(database)
            logging.info("Creating database")
            self.db = pickledb.load(database, False)
        
    # Creates folders for customers.
    def create_customer_folder(self, customer_name):
        """
	    Creates a directory for a customer to save offenses. Used for backlogging.
        """
        customer_dir = "%s/database/customers/%s" % (dir_path, customer_name )
        if not os.path.exists(customer_dir):
            os.makedirs(customer_dir)

        
    # Creates database for customer if it doesnt exist and SEC token exists
    def create_db(self, name):
        """
	    Uses pickledb to keep track of latest offenses.
        """
        self.db_setup()
        self.create_customer_folder(name)
        if not name in self.db.getall():
            self.db.lcreate(name)
            self.db.ladd(name, 0)
            self.db.set(name+"_counter", 0)
            self.db.set(name+"_status_code", 200)
            self.db.set(name+"_code_status", 0)
            self.db.dump()
            logging.info("%s Initialized database for %s" % (self.get_time, name))
            return False
        return True

    # Gets current time for print format.
    def get_time(self):
		# Workaround for wrong time
        hourstr = time.strftime("%H")
        hourint = int(hourstr)+2
        return "%d:%s" % (hourint, time.strftime("%M:%S"))

    # Reloading the complete customers object for every iteration
    def add_customers(self, customer_json):
        """
			Creates customer object => Loops through each and every one 
			and verifies if they exist or not in the customer list. (self.customers)
        """

        self.customers = []
        # Catches exception related to unbound variables
        try:
            for item in customer_json:
                try:
                    # Verifies Json data
                    if item['SEC'] and len(item['SEC']) is 36:
                        a = Customer(item['name'], item['SEC'], \
                                     item['target'], item['version'], \
                                     item['rules'], item['subnet'], \
                                     item['cert'], item['domain'])
                        logging.info("%s: Customer %s added/reloaded to customer" % (self.get_time(), item['name']))
                        self.create_db(item['name'])
                        self.customers.append(a)
                    else:
                        logging.info("%s: No SEC token found for %s" % (self.get_time(), item['name']))
                except KeyError as e:
                    logging.warning("%s: Bad key: %s" % (self.get_time(), e))
                    continue
        except UnboundLocalError:
            return

    # Checks if the json is valid with expected inputs
    def load_objects(self, customers = []):
        """
			Verifies if the JSON interpreted contains errors and if it should be refreshed or not.
			THis function exists to make real-time addition of new customers possible.
        """
        global json_time
        file = "%s/database/customer.json" % dir_path

        # Verifies if file has been edited.
        if os.path.getmtime(file) > json_time:
            json_time = os.path.getmtime(file)
            msg = "%s: Reloading %s because of timedifference" % (self.get_time(), file)
            if len(sys.argv) > 1:
                if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                	print(msg)

            self.write_offense_log(msg) 

            logging.info("%s: Reloading %s because of timedifference" % (self.get_time(), file))
        else:
            logging.info("%s: No changes made to %s" % (self.get_time(), file))
            return

        try:
            with open(file, 'r') as tmp: 
                #self.verify_json(open(file, 'r'))
                customer_json = json.loads(tmp.read())
        except IOError as e:
            logging.info("%s: %s" % (self.get_time(), e))
            return
        except ValueError as e:
            logging.info("%s: %s" % (self.get_time(), e))
            return 

        # Create customer info 
        customer_value = self.add_customers(customer_json)
        return customer_value
        
    # Uses Sveve for SMS sending
    def send_sms(self, message):
        """
	    Originally made to send an SMS with the message variable to a specific number.
        """
        logging.info("%s: %s" % (self.get_time(), "Attempting to send sms"))

        if isinstance(message, dict):
            message = "\n".join(message['categories'])

        passwd=""

        # Measure to not make api calls for SMS service.
        if not passwd:
            logging.info("%s: %s" % (self.get_time(), "Aborting sms sending"))
            return

        username = "hmm /o\\"
        url = "https://sveve.no/SMS/SendMessage?"
        target = ""
        sender = "IT ME"

        tot_url = "%suser=%s&passwd=%s&to=%s&from=%s&msg=%s - %s" % (url, username, passwd, target, sender,  message['id'], message)
        tot_url += "%20SMS"
        logging.info("%s: should send alarm for ****\n%s" % (self.get_time(), tot_url))

        try:
            request = requests.get(tot_url, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        return 

    # Runs the alarm
    def run_alarm(self, item, customer):
        """
	    Originally used to control on-screen offenses, but later found to be annoying.
        """
        logging.info("%s: New highest offense - %s - customer %s, %s" % \
            (self.get_time(), item['id'], customer.name, item['categories']))

        if self.db.get(customer.name+"_counter") is 0:
            self.db.set(customer.name+"_counter", \
            int(self.db.get(customer.name+"_counter"))+1)
            return

        logging.warning("%s: Sending alarm to %s" % (self.get_time(), customer.name))
        new_data = urllib.quote("Offense #%s: %s" % \
                            (item['id'], "\n".join(item['categories'])))

        # Return to only get one alarm at a time per customer.
        return False

    def reverse_list(self, customer, request):
        """
			Reverses a list. QRadar API > 7.0 wasn't stable.
        """
        tmp_arr = []
        if not customer.new_version:
            for i in range(len(request.json())-1, -1, -1):
                tmp_arr.append(request.json()[i])
            return tmp_arr
        else:
            return request.json()

    # Removes the "Range" header for some specific API calls.
    def remove_range_header(self, customer):
        """
			Removes a specific header. Depends on which API call is used.
        """
        headers = dict.copy(customer.header)

        try:
            del headers["Range"] 
        except KeyError as e:
            logging.warning("%s: Bad key: %s" % (self.get_time(), e))
        return headers

    # If it doesn't exist already
    def find_ip(self, customer, ID, headers, src_dst="src"):
        """
			Finds and IP based on ID.
			Almost same as above, but not in bulk.
        """
        search_field = ""
        find_ip = ""

        if src_dst == "dst":
            src_dst = "local_destination_addresses" 
            search_field = "local_destination_ip"
        else:
            src_dst = "source_address_ids" 
            search_field = "source_ip"

        target_path = "https://%s/api/siem/%s" % (customer.target, src_dst)
        header = self.remove_range_header(customer)

        try:
            find_ip = requests.get(target_path+"/%s?fields=id%s%s" % \
                (str(ID), "%2C", search_field), headers=header, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        try:
            ret_val = find_ip.json()[search_field]
        except (KeyError, UnboundLocalError) as e:
            ret_val = False

        return ret_val

    # Gets the a list of IDs related to IPs 
    def get_reflist(self, customer, ref_name):
        """
            Gets the actual data used to correlate with customer.json rules.
        """
        fields = ""
        headers = self.remove_range_header(customer)
        
        ref_list = "https://%s/api/reference_data/sets/%s" % (customer.target, ref_name) 

        try:
            ref_set = requests.get("%s" % ref_list, headers=headers, timeout=5, verify=False)
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))

        return ref_set

    def get_network_list(self, network_list):
        """
	    Finds the list of networks that are more valuable (e.g. server network)
        """
        arr = []
        for subnet in network_list:
            arr.append(subnet["value"])

        return arr

    # Returns 
    def get_affected_subnet(self, req, customer, network_list, id_list_name, src_dst):
        """
            Checks if the network found in an offense is part of the actual subnet
        """
        affected_subnet = []
        headers = self.remove_range_header(customer)

        if src_dst == "dst":
            ip_variable = "local_destination_ip"
            base_url = "https://%s/api/siem/local_destination_addresses/" % customer.target
            fields = "?fields=local_destination_ip" 
        elif src_dst == "src":
            ip_variable = "source_ip"
            base_url = "https://%s/api/siem/source_addresses/" % customer.target
            fields = "?fields=source_ip" 

        for ID in req.json()[id_list_name]:
            url = base_url+str(ID)+fields
            cnt = 0


            try:
                ip = requests.get(url, headers=headers, verify=False, timeout=5)
            except requests.exceptions.ConnectionError:
                continue

            try:
                ip = ip.json()[ip_variable]
            except KeyError as e:
                logging.warning("%s: %s" % (self.get_time(), e))
                continue

            for network in network_list:
                try:
                    if ip in netaddr.IPNetwork(network):
                        return ip

                except netaddr.core.AddrFormatError as e:
                    logging.warning("%s: %s" % (self.get_time(), e))
                    cnt += 1

        return False

    # Verifies alarms related to reference lists
    def verify_reflist(self, customer, req):
        """
            Verifies multiple reference set alarms. 
        """

        id_list = ["source_address_ids", "local_destination_address_ids"]
    
        affected_subnet = []

        # List of subnets to check
        for ref_set_list in customer.ref_list:
            ref_set = self.get_reflist(customer, ref_set_list)

            # Works because < 255
            if not ref_set.status_code is 200:
                logging.warning("Cannot access reflist.")
                continue

            try:
                network_list = self.get_network_list(ref_set.json()["data"])
            except KeyError as e:
                logging.warning("%s: %s" % (self.get_time(), e))
                if ref_set.json()["number_of_elements"] is 0:
                    msg = "%s might be empty for %s, no action taken." \
                            % (ref_set_list, customer.name)

                    if len(sys.argv) > 1:
                    	if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                    		print(msg)

                    self.write_offense_log(msg) 
					

                continue

            src_affected_subnet = self.get_affected_subnet(req, customer, \
                    network_list, "source_address_ids", "src")
            if src_affected_subnet:
                #sys.stdout.write("SUBNET %s. " % src_affected_subnet)
                return True

            dst_affected_subnet = self.get_affected_subnet(req, customer, \
                    network_list, "local_destination_address_ids", "dst")

            if dst_affected_subnet:
                return True

        return False

    def check_alarm(self, ID, customer):
        """
            Verifies an ID, if it's new etc. Bulk loads and checks if the lowest number 
            is greater than the oldest saved one.
            The horrible forloop verifies if rules are matched based on rules in customer.json
        """
        fields = ""
        valid = True 

        headers = self.remove_range_header(customer)

        try:
            req = requests.get("https://%s/api/siem/offenses/%s%s" % (customer.target, str(ID), fields),\
                     timeout=5, headers=headers, verify=False) 
        except (requests.exceptions.ConnectionError,\
                requests.exceptions.ReadTimeout,\
                AttributeError) as e:
            logging.warning("%s: %s" % (self.get_time(), e))
            return False

        if req.status_code != 200:
            logging.warning("%s Unable to retrieve %s" % (self.get_time(), customer.target))
            return False

        # Checks reference lists from database/customer.json
        if customer.ref_list[0]:
            valid = self.verify_reflist(customer, req) 
        else:
            return False
    
        # Skips if reference list match
        # Can add alarm sending in this one
        
        if not valid:
            return False

        logging.info("%s: %s" % (self.get_time(), \
            "In subnet range. Verifying rules for %s" % customer.name))

        # Checks rules only if offense contains IP in specified IP range
        rule_counter = 0
        for rules in customer.rules: 
            # Iter keys inside rule
            for keys, values in rules.iteritems():
                # Do stuff if not integer values
                if not isinstance(values, int):
                    if values == ".*":
                        rule_counter += 1
                        continue
                    # Checks multiple arguments in same rule split on "|". 
                    for split_item in values.split("|"):
                        for categories in req.json()[keys]:
                            if split_item.lower().startswith("!") \
                                and split_item.lower()[1:] in categories.lower():
                                return False
                                #rule_counter -= 1

                            if split_item.lower() in categories.lower(): 
                                rule_counter += 1

                # INT CHECK
                else:
                    if req.json()[keys] > values:
                        rule_counter += 1
                    else:
                        break

            # Runs alarm if counter is high enough. 
            if rule_counter is len(rules):
                msg = "RULES MATCHED. SHOULD SEND ALARM \o/"
                if len(sys.argv) > 1:
                	if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                		print(msg)

                self.write_offense_log(msg) 
					
                logging.info("%s: Rule triggered - sending alarm" % self.get_time())
                self.run_alarm(req.json(), customer)
                break

            rule_counter = 0
        return True

    # Verify ID here
    def add_new_ID(self, customer, request):
        path = "database/customers/%s/%s" % (customer.name, str(request.json()["id"]))

        if not os.path.exists(path):
            with open(path, "w+") as tmp:
                json.dump(request.json(), tmp)

        logging.info("%s: Added new offense to %s" % (self.get_time(), path))

    # DISCORD SETUP 
    def discord_setup(self, ID, msg):
        alarm_msg = "%s - %s" % (ID, msg)
        call = ["python3.6", "%s/dependencies/chat.py" % dir_path, "\"%s\"" % alarm_msg]
        subprocess.call(" ".join(call), shell=True)
        logging.info("%s: Message sent to discord server." % self.get_time())

    # BEST LOGGER AYY \o/ LMAO
    def write_offense_log(self, data):
        with open("log/offense.log", "a") as tmp:
            try:
                tmp.write("\n%s" % str(data))
            except UnicodeEncodeError as e:
                tmp.write("\nError in parsing data.\n%s" % e)

    # Returns tasklist based on casetitle
    def get_hive_task_data(self, data):
        # Reload every time so it's editable while running.
        with open(cfg.incident_task, "r") as tmp:
            cur_data = json.load(tmp)

        # Is cur_data["description"] in data["description"]:
        for item in json.load(open(cfg.incident_task, "r"))["ruleslist"]:
            if item["description"].lower() in data["description"].lower():
                return item["result"]

    # Checks the normal local subnet ranges. Theres like 7 missing.
    def check_local_subnet(self, ip_address):
        # Returns false if ip not a local address 
        # Yes I know there are more..
        local_ranges = [
            "192.168.0.0/16",
            "172.16.0.0/12",
            "10.0.0.0/8"
        ]

        for item in local_ranges:
            if netaddr.IPAddress(ip_address) in netaddr.IPNetwork(item): 
                return False 

        return True 

    # IP verification lmao
    def verify_offense_source(self, input):
        try:
            netaddr.IPAddress(str(input))
            if not self.check_local_subnet(input):
                return False

            return True
        except netaddr.core.AddrFormatError:
            return False

    # Returns all IPs in an offense by ID
    def get_ip_data(self, customer, data):
        verify_local_ip = [] 

        # Should prolly cache this data.
        # Finds IPs based on and ID - destination
        if data["local_destination_count"] > 0:
            for item in data["local_destination_address_ids"]:
                ip_output = self.find_ip(customer, item, customer.header, "dst")
                if ip_output:
                    if ip_output not in verify_local_ip and self.check_local_subnet(ip_output):
                        verify_local_ip.append(str(ip_output))

        # Finds IPs based on and ID - source 
        if data["source_count"] > 0:
            for item in data["source_address_ids"]:
                ip_output = self.find_ip(customer, item, customer.header)
                if ip_output:
                    if ip_output not in verify_local_ip and self.check_local_subnet(ip_output):
                        verify_local_ip.append(str(ip_output))

        return verify_local_ip

    # Only created for IP currently.
    # Hardcoded for QRadar
    def get_hive_cases(self, customer, data):
        # Offense doesn't return all the IP-addresses.
        verify_local_ip = self.get_ip_data(customer, data)
        find_source = self.verify_offense_source(data["offense_source"])
        
        # Adds offense source if IP observed
        if find_source:
            verify_local_ip.append(str(data["offense_source"]))

        # Returns if no observables found
        # Also means a case will not be created.
        if not verify_local_ip:
            return False

        # Check basic case details first. Customername > Name of offense > category
        # Might be able to search title field for customer name as well. Tags can also be used.
        allcases = self.hive.find_cases(query={"_field": "status", "_value": "Open"})
        customer_caselist = []

        # Finds all the specified customers cases
        for item in allcases.json():
            if customer.name.lower() in item["title"].lower():
                customer_caselist.append(item)

        # Creates a case if no cases are found. Returns list of observed IoCs for case creation
        if not customer_caselist:
            return verify_local_ip 

        use_case = ""
        casename = ""
        # Looks for exact casename match 
        for case in customer_caselist:
            casetitle = case["title"].split(" - ")[1]
            if casetitle == data["description"]:
                use_case = case
                break

        if use_case:
            not_matching = []
            matching_categories = data["categories"]

        # Try to match two categories if exact name match isn't found
        if not use_case:
            # Least amount of categories needed to match
            category_match_number = 2

            category_counter = 0
            for case in customer_caselist:
                matching_categories = []
                not_matching = []
                for category in data["categories"]: 
                    if category in case["tags"]:
                        matching_categories.append(category)
                    else:
                        not_matching.append(category)

                if len(matching_categories) > (category_match_number-1):
                    use_case = case
                    break

        # Will create a new case if observable found and no similar case.
        if not use_case:
            return verify_local_ip 
                 
        # FIX - Hardcoded datatype
        datatype = "ip"
        actual_data = []

        # Finds actual observables for the specified case
        observables = [x["data"] for x in self.hive.get_case_observables(\
            use_case["id"]).json() if x["dataType"] == datatype]

        # Finds if observable exists in previous list
        actual_data = [x for x in verify_local_ip if not x in observables]

        # FIX - check logic here. Might need to add tags etc (offenseID) etc.
        # Only appends data if new observables are detected
        if not actual_data:
            return False

        # Defines what categories to append
        category_breaker = ""
        if not_matching:
            category_breaker = not_matching
        else:
            category_breaker = matching_categories
            
        self.add_observable_data(use_case["id"], actual_data, datatype, data, not_matching) 

        # False to not create another case
        return False

    # Add by caseid and list of specified datatype and a QRadar offense
    def add_observable_data(self, case_id, observables, datatype, data, category):
        observable_items = []
        data_items = []

        tags = [str(data["id"])]
        tags.extend(category)

        for item in observables:
            observable = CaseObservable(
                dataType=datatype,
                data=item,
                tlp=0,
                ioc=True,
                tags=tags,
                message="Possible IoC"
            )

            # Creates the observable
            ret = self.hive.create_case_observable(case_id, observable)
            if ret.ok:
                observable_items.append(ret.json())
                data_items.append(item)
            else:
                continue

        if data_items:
            self.cortex_listener.run_cortex_analyzer(datatype, data_items, observable_items)

    # TheHive case creation
    def create_hive_case(self, customer, data):
        create_hive_bool = self.get_hive_cases(customer, data)

        # Returns if case already merged.
        if not create_hive_bool:
            return False

        # Baseline for creating a case
        title = ("%s: %s - %s" % (customer.name, str(data["id"]), data["description"]))
	static_task = "Why did it happen? Check rule.",
        task_data = self.get_hive_task_data(data)
        tasks = [
            CaseTask(title=static_task)
        ]
        if task_data:
            for item in task_data:
                tasks.append(CaseTask(title=item))

        # Creates a case object
        case = Case(title=title, tlp=0, flag=False, tags=data["categories"], \
                description=data["description"], tasks=tasks)

        # Creates the actual case based on prior info
        ret = self.hive.create_case(case)

        if ret.ok:
            # FIX, datatype is static
            self.add_observable_data(ret.json()["id"], create_hive_bool, \
                "ip", data, data["categories"])
            return True 

        return False

    # Verifies the ID, and returns if it's not a new incident.
    def verify_ID(self, request, customer):
        # In case there are no offenses related to customer. Basically domain management.
        # Attempts to reanalyze in case of failed analysis jobs

        #self.cortex_listener.find_failed_cortex_jobs()

        try:
            if float(customer.version) < 7.0:
                try:
                    json_id = request.json()[len(request.json())-1]['id']
                except (ValueError, IndexError) as e:
                    logging.warning("%s: Customer %s: %s" % (self.get_time(), customer.name, e))
                    return False
                customer.new_version = False
            else:
                json_id = request.json()[0]['id']
        except IndexError:
            logging.info("No offenses for customer.")
            return

        # Use difference between last seen offense and newest.
        last_db = self.db.lget(customer.name, self.db.llen(customer.name)-1)
        cur_array = []
        if json_id > last_db:
            difference = 1

            # Not even a point /o\
            if not json_id-last_db is difference:
                difference = json_id-last_db

            # Looping through incase of earlier crash / multiple offenses in one minute
            for i in range(json_id, last_db, -1):
                cur_var = False 
                if i in self.db.get(customer.name):
                    continue

                # Verifies if the id actually exists
                for item in request.json():
                    if i == item['id']:
                        cur_var = True
                        break

                if not cur_var:
                    continue      

                logging.info("%s: %s: New highest offense found: %d" % (self.get_time(), customer.name, i))

                target = "https://%s/api/siem/offenses/%s" % (customer.target, str(i))
                new_header = self.remove_range_header(customer)

                try:
                    new_req = requests.get(target, headers=new_header, timeout=5, verify=False)
                except requests.exceptions.ConnectionError as e:
                    logging.warning("Internal alarmserver might be down: %s" % e)
                    continue
                except requests.exceptions.ReadTimeout as e:
                    logging.warning("Timeout %s" % e)
                    continue
                # Appends current offense to database/customers/customer/ID in json format. 
                # This is to backtrack 
                ID_ret = self.add_new_ID(customer, new_req)
                new_req = new_req.json()

                try: 
                    # Compatibility issue if missing prerequisites.
                    new_data = urllib.quote("Offense #%s: %s" % (str(i), \
                                     "\n".join(new_req['categories'])))
                except TypeError as e:
                    logging.warning("%s: TypeError: %s" % (self.get_time(), e))
                    new_data = urllib.quote("Offense #%s: %s" % (str(i), "Arbitrary categories"))
                except KeyError as e:
                    logging.warning("%s: KeyError: %s" % (self.get_time(), e))
                    new_data = urllib.quote("Offense #%s: %s" % (str(i), "Arbitrary categories"))

                # Sends a local alarm if an alarmserver is running on the current system. 

                # Prints to screen. Try/catch only in case of errors.
                try:
                    msg = "%s: %s - %s - %s" % (self.get_time(), \
                        str(i).ljust(5), customer.name.ljust(10), ", ".join(new_req['categories']))
                    if len(sys.argv) > 1:
                    	if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
                    		print(msg)

                    self.write_offense_log(msg) 
					
                except TypeError as e:
                    logging.warning("%s: TypeError: %s" % (self.get_time(), e))
                except KeyError as e:
                    logging.warning("%s: KeyError: %s" % (self.get_time(), e))

                if cfg.TheHive:
                    self.create_hive_case(customer, new_req) 
                if cfg.discordname and cfg.discordpw:
                    self.discord_setup(str(i), ", ".join(new_req['categories']))

                # verifying if an alarm should be triggered.
                difference = json_id-self.db.llen(customer.name)-1

                # Adds data to the DB
                cur_array.append(i)

                alarm_check = self.check_alarm(i, customer)
                if not alarm_check:
                    continue 

            # Adds all the data to the database
            if cur_array:
                cur_array = sorted(cur_array)

                for items in cur_array:
                    self.db.ladd(customer.name, items)

                
        else:
            return False
	
    # Reload json every time, and check it to prevent failures. verify_json(self, x) 
    def check_connection(self):
        global resetcounter
        for customer in self.customers:
            self.db.dump()
            domain_field = ""
            self.db.set(customer.name+"_counter", int(self.db.get(customer.name+"_counter"))+1)

            # Verifies status codes
            if not self.db.get(customer.name+"_status_code") is 200 \
                and customer.fail_counter % 10 > 0:
                continue

            # Domain management because of some bullshit.
            if customer.domain > 0:
                domain_field = "?filter=domain_id%s%d" % (r'%3D', customer.domain)

            # Makes original request per customer
            try:
                request = requests.get('%s%s' % (customer.target_path, domain_field), \
                    headers=customer.header, timeout=5, verify=False)
            except (requests.exceptions.ConnectionError,\
                    requests.exceptions.ReadTimeout,\
                    AttributeError) as e:
                try:
                    logging.info("%s: Connection failure for %s" % \
                                (self.get_time(), customer.name))
                    continue
                except TypeError as e:
                    logging.warning("%s" % e)
                    self.db.set(customer.name+"_status_code", 401)
                    continue

            # Set previous status code?
            # Legacy, but doesn't hurt nothing \o/
            if request.status_code != 200:
                logging.info("%s: Not 200 for %s - %s" % (self.get_time(), customer.name, \
                            self.db.get(customer.name+"_status_code")))
                self.db.set(customer.name+"_status_code", request.status_code)
                continue
                
            # Sets previous status code in case of shutdown
            self.db.set(customer.name+"_status_code", request.status_code)

            verify_request = self.verify_ID(request, customer)
            if not verify_request: 
                continue

def loop():
    """
        Loops about every minute, base
    """
    t = Offense()
    msg = "%s: Server starting" % t.get_time()

    if len(sys.argv) > 1:
        if sys.argv[1] == "--verbose" or sys.argv[1] == "-v":	
        	print(msg)

    t.write_offense_log(msg) 
    logging.info("%s: Restarting script" % time.strftime("%Y:%M:%d, %H:%M:%S"))

    while(1):
        test = t.load_objects()
        t.check_connection()
        time.sleep(60)

# OHAI
if __name__ == "__main__":
    try:
        loop()
    except KeyboardInterrupt:
        print('\nProgram interrupted. \"python get_offense.py\" to restart.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
